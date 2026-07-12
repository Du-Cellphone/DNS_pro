#include "DNS.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <utility>

DNS::~DNS()
{
    request_stop();
    join();
}

bool DNS::init(const DNSConfig &config)
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (state_ == State::Running || state_ == State::Stopping)
        return false;
    if (config.worker_count == 0 || config.manager_count > 1 || (config.port == 0 && config.worker_count > 1))
        return false;

    try
    {
        auto cache = std::make_unique<Cache::DNS_Cache>(config.cache_capacity, config.worker_count);
        auto context = std::make_shared<const FilterContext>();

        cache_ = std::move(cache);
        active_context_.store(std::move(context), std::memory_order_release);
        config_ = config;
        state_ = State::Initialized;
        return true;
    }
    catch (const std::exception &error)
    {
        std::cerr << "failed to initialize DNS service: " << error.what() << '\n';
        return false;
    }
}

bool DNS::init(size_t worker_thread_count, size_t manager_thread_count)
{
    DNSConfig config;
    config.worker_count = worker_thread_count;
    config.manager_count = manager_thread_count;
    return init(config);
}

bool DNS::start()
{
    std::unique_lock lock{lifecycle_mutex_};
    if (state_ != State::Initialized || !cache_)
        return false;

    std::vector<std::unique_ptr<WorkerContext>> contexts;
    contexts.reserve(config_.worker_count);
    for (size_t worker_id = 0; worker_id < config_.worker_count; ++worker_id)
    {
        auto context = std::make_unique<WorkerContext>();
        context->worker_id = worker_id;
        context->cache_shard = &cache_->shard(worker_id);
        if (!init_network_env(*context, config_.port))
            return false;
        contexts.push_back(std::move(context));
    }

    worker_contexts_ = std::move(contexts);
    try
    {
        worker_threads_.reserve(config_.worker_count);
        for (const auto &context : worker_contexts_)
        {
            WorkerContext *worker_context = context.get();
            worker_threads_.emplace_back([this, worker_context](std::stop_token token) { worker(token, *worker_context); });
        }

        manager_threads_.reserve(config_.manager_count);
        for (size_t index = 0; index < config_.manager_count; ++index)
            manager_threads_.emplace_back([this](std::stop_token token) { manager(token); });
    }
    catch (const std::exception &error)
    {
        std::cerr << "failed to start DNS threads: " << error.what() << '\n';
        for (auto &thread : worker_threads_)
            thread.request_stop();
        for (const auto &context : worker_contexts_)
            context->wake();
        for (auto &thread : manager_threads_)
            thread.request_stop();
        manager_wakeup_.notify_all();

        std::vector<std::jthread> failed_workers;
        std::vector<std::jthread> failed_managers;
        failed_workers.swap(worker_threads_);
        failed_managers.swap(manager_threads_);
        lock.unlock();
        failed_workers.clear();
        failed_managers.clear();
        lock.lock();
        worker_contexts_.clear();
        return false;
    }

    state_ = State::Running;
    return true;
}

void DNS::request_stop() noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (state_ != State::Running && state_ != State::Stopping)
        return;

    state_ = State::Stopping;
    for (auto &thread : worker_threads_)
        thread.request_stop();
    for (const auto &context : worker_contexts_)
        context->wake();
    for (auto &thread : manager_threads_)
        thread.request_stop();
    manager_wakeup_.notify_all();
}

void DNS::join() noexcept
{
    request_stop();

    std::vector<std::jthread> workers;
    std::vector<std::jthread> managers;
    {
        std::scoped_lock lock{lifecycle_mutex_};
        workers.swap(worker_threads_);
        managers.swap(manager_threads_);
    }

    workers.clear();
    managers.clear();

    std::scoped_lock lock{lifecycle_mutex_};
    worker_contexts_.clear();
    if (state_ == State::Stopping || state_ == State::Running)
        state_ = State::Stopped;
}

bool DNS::is_running() const noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    return state_ == State::Running;
}

void DNS::worker(std::stop_token stop_token, WorkerContext &context) noexcept
{
    std::array<epoll_event, 64> events{};
    std::array<uint8_t, 4096>   buffer{};

    while (!stop_token.stop_requested())
    {
        const int ready = ::epoll_wait(context.epoll_fd.get(), events.data(), static_cast<int>(events.size()), -1);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
            std::cerr << "worker " << context.worker_id << " epoll_wait failed: " << std::strerror(errno) << '\n';
            break;
        }

        for (int index = 0; index < ready; ++index)
        {
            if (events[static_cast<size_t>(index)].data.u64 == kWakeEvent)
            {
                context.drain_wakeup();
                continue;
            }
            if (events[static_cast<size_t>(index)].data.u64 != kListenerEvent)
                continue;

            while (!stop_token.stop_requested())
            {
                sockaddr_storage client_address{};
                socklen_t        client_length = sizeof(client_address);
                const ssize_t received = ::recvfrom(context.listen_fd.get(), buffer.data(), buffer.size(), 0,
                                                    reinterpret_cast<sockaddr *>(&client_address), &client_length);
                if (received >= 0)
                    continue;
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                std::cerr << "worker " << context.worker_id << " recvfrom failed: " << std::strerror(errno) << '\n';
                break;
            }
        }
    }
}

void DNS::manager(std::stop_token stop_token) noexcept
{
    std::mutex              wait_mutex;
    std::unique_lock        lock{wait_mutex};
    manager_wakeup_.wait(lock, stop_token, [] { return false; });
}

bool DNS::init_network_env(WorkerContext &context, uint16_t port)
{
    dns::runtime::UniqueFd listener{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (!listener)
    {
        std::cerr << "failed to create UDP socket: " << std::strerror(errno) << '\n';
        return false;
    }

    int enabled = 1;
    if (::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) < 0 ||
        ::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)) < 0)
    {
        std::cerr << "failed to configure UDP socket: " << std::strerror(errno) << '\n';
        return false;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (::bind(listener.get(), reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0)
    {
        std::cerr << "failed to bind UDP socket: " << std::strerror(errno) << '\n';
        return false;
    }

    dns::runtime::UniqueFd epoll{::epoll_create1(EPOLL_CLOEXEC)};
    if (!epoll)
    {
        std::cerr << "failed to create epoll: " << std::strerror(errno) << '\n';
        return false;
    }

    dns::runtime::UniqueFd wake{::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)};
    if (!wake)
    {
        std::cerr << "failed to create worker eventfd: " << std::strerror(errno) << '\n';
        return false;
    }

    epoll_event listener_event{};
    listener_event.events = EPOLLIN | EPOLLET;
    listener_event.data.u64 = kListenerEvent;
    if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, listener.get(), &listener_event) < 0)
    {
        std::cerr << "failed to register UDP socket with epoll: " << std::strerror(errno) << '\n';
        return false;
    }

    epoll_event wake_event{};
    wake_event.events = EPOLLIN;
    wake_event.data.u64 = kWakeEvent;
    if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, wake.get(), &wake_event) < 0)
    {
        std::cerr << "failed to register eventfd with epoll: " << std::strerror(errno) << '\n';
        return false;
    }

    context.listen_fd = std::move(listener);
    context.epoll_fd = std::move(epoll);
    context.wake_fd = std::move(wake);
    return true;
}
