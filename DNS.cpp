#include "DNS.h"

#include <cstring>
#include <iostream>
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
    if (config.worker_count == 0 || config.manager_count > 1 || (config.port == 0 && config.worker_count > 1) ||
        !dns::server::is_valid_upstream_config(config.upstream))
        return false;

    try
    {
        DNSConfig configured = config;
        auto      context    = dns::server::build_filter_snapshot(configured.blocked_domains);
        if (!context)
        {
            std::cerr << "failed to initialize blocklist at rule " << context.error().rule_index << '\n';
            return false;
        }
        auto cache = std::make_unique<Cache::DNS_Cache>(configured.cache_capacity, configured.worker_count);

        config_ = std::move(configured);
        cache_ = std::move(cache);
        active_context_.store(std::move(*context), std::memory_order_release);
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

    std::vector<std::unique_ptr<dns::server::WorkerLoop>> loops;
    loops.reserve(config_.worker_count);
    try
    {
        for (size_t worker_id = 0; worker_id < config_.worker_count; ++worker_id)
        {
            auto loop =
                dns::server::WorkerLoop::create(worker_id, config_.port, cache_->shard(worker_id), active_context_, config_.upstream);
            if (!loop)
            {
                std::cerr << "failed to initialize worker " << worker_id << " at step " << static_cast<int>(loop.error().step)
                          << ": " << std::strerror(loop.error().error_number) << '\n';
                return false;
            }
            loops.push_back(std::move(*loop));
        }
    }
    catch (const std::exception &error)
    {
        std::cerr << "failed to allocate worker reactors: " << error.what() << '\n';
        return false;
    }

    worker_loops_ = std::move(loops);
    try
    {
        worker_threads_.reserve(config_.worker_count);
        for (const auto &loop : worker_loops_)
        {
            dns::server::WorkerLoop *worker_loop = loop.get();
            worker_threads_.emplace_back([worker_loop](std::stop_token token) { worker_loop->run(token); });
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
        for (const auto &loop : worker_loops_)
            loop->request_stop();
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
        worker_loops_.clear();
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
    for (const auto &loop : worker_loops_)
        loop->request_stop();
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
    worker_loops_.clear();
    if (state_ == State::Stopping || state_ == State::Running)
        state_ = State::Stopped;
}

bool DNS::is_running() const noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    return state_ == State::Running;
}

std::optional<uint16_t> DNS::bound_port() const noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (worker_loops_.empty())
        return std::nullopt;
    return worker_loops_.front()->bound_port();
}

void DNS::manager(std::stop_token stop_token) noexcept
{
    std::mutex       wait_mutex;
    std::unique_lock lock{wait_mutex};
    manager_wakeup_.wait(lock, stop_token, [] { return false; });
}
