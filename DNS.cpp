#include "DNS.h"

#include <cstring>
#include <iostream>
#include <utility>

namespace
{

dns::server::FilterUpdateResult filter_update_error(dns::server::FilterUpdateErrorCode code)
{
    return std::unexpected(dns::server::FilterUpdateError{code, std::nullopt});
}

} // namespace

DNS::~DNS()
{
    request_stop();
    join();
}

bool DNS::init(const DNSConfig &config)
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (state_ == State::Starting || state_ == State::Running || state_ == State::Stopping)
        return false;
    if (config.worker_count == 0 || config.manager_count > 1 || (config.port == 0 && config.worker_count > 1) ||
        !dns::server::is_valid_upstream_config(config.upstream))
        return false;

    try
    {
        auto context = dns::server::build_filter_snapshot(config.blocked_domains, dns::server::kInitialFilterGeneration);
        if (!context)
        {
            std::cerr << "failed to initialize blocklist at rule " << context.error().rule_index << '\n';
            return false;
        }

        auto filter_updates = std::make_unique<dns::server::FilterUpdateController>(std::move(*context));
        auto cache          = std::make_unique<Cache::DNS_Cache>(config.cache_capacity, config.worker_count);

        config_ = RuntimeConfig{
            .worker_count   = config.worker_count,
            .manager_count  = config.manager_count,
            .cache_capacity = config.cache_capacity,
            .port           = config.port,
            .upstream       = config.upstream,
        };
        filter_updates_ = std::move(filter_updates);
        cache_          = std::move(cache);
        worker_loops_.clear();
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
    config.worker_count  = worker_thread_count;
    config.manager_count = manager_thread_count;
    return init(config);
}

bool DNS::start()
{
    std::unique_lock lock{lifecycle_mutex_};
    if (state_ != State::Initialized || !cache_ || !filter_updates_)
        return false;

    state_ = State::Starting;
    std::vector<std::unique_ptr<dns::server::WorkerLoop>> loops;
    std::vector<std::jthread>                             workers;
    std::vector<std::jthread>                             managers;

    try
    {
        loops.reserve(config_.worker_count);
        for (size_t worker_id = 0; worker_id < config_.worker_count; ++worker_id)
        {
            auto loop = dns::server::WorkerLoop::create(worker_id, config_.port, cache_->shard(worker_id), filter_updates_->snapshot_slot(),
                                                        config_.upstream);
            if (!loop)
            {
                std::cerr << "failed to initialize worker " << worker_id << " at step " << static_cast<int>(loop.error().step) << ": "
                          << std::strerror(loop.error().error_number) << '\n';
                state_ = State::Initialized;
                return false;
            }
            loops.push_back(std::move(*loop));
        }

        workers.reserve(config_.worker_count);
        for (const auto &loop : loops)
        {
            dns::server::WorkerLoop *worker_loop = loop.get();
            workers.emplace_back([worker_loop](std::stop_token token) { worker_loop->run(token); });
        }

        managers.reserve(config_.manager_count);
        for (size_t index = 0; index < config_.manager_count; ++index)
            managers.emplace_back([this](std::stop_token token) { manager(token); });
    }
    catch (const std::exception &error)
    {
        std::cerr << "failed to start DNS threads: " << error.what() << '\n';
        for (auto &thread : managers)
            thread.request_stop();
        for (auto &thread : workers)
            thread.request_stop();
        for (const auto &loop : loops)
            loop->request_stop();
        managers.clear();
        workers.clear();
        state_ = State::Initialized;
        return false;
    }

    worker_loops_    = std::move(loops);
    worker_threads_  = std::move(workers);
    manager_threads_ = std::move(managers);
    state_           = State::Running;
    return true;
}

void DNS::request_stop() noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    request_stop_locked();
}

void DNS::join() noexcept
{
    std::scoped_lock join_lock{join_mutex_};

    std::vector<std::jthread> workers;
    std::vector<std::jthread> managers;
    {
        std::scoped_lock lock{lifecycle_mutex_};
        if (state_ != State::Running && state_ != State::Stopping)
            return;

        request_stop_locked();
        workers.swap(worker_threads_);
        managers.swap(manager_threads_);
    }

    managers.clear();
    workers.clear();

    std::scoped_lock lock{lifecycle_mutex_};
    worker_loops_.clear();
    if (state_ == State::Stopping || state_ == State::Running)
        state_ = State::Stopped;
}

dns::server::FilterUpdateResult DNS::replace_blocked_domains(std::vector<std::string> rules)
{
    try
    {
        dns::server::FilterUpdateFuture future;
        {
            std::scoped_lock lock{lifecycle_mutex_};
            if (state_ == State::Stopping || state_ == State::Stopped)
                return filter_update_error(dns::server::FilterUpdateErrorCode::ShuttingDown);
            if (state_ != State::Running)
                return filter_update_error(dns::server::FilterUpdateErrorCode::ServiceNotRunning);
            if (config_.manager_count == 0)
                return filter_update_error(dns::server::FilterUpdateErrorCode::ControlPlaneDisabled);
            if (!filter_updates_)
                return filter_update_error(dns::server::FilterUpdateErrorCode::InternalError);

            future = filter_updates_->submit_replace(std::move(rules));
        }
        return future.get();
    }
    catch (...)
    {
        return filter_update_error(dns::server::FilterUpdateErrorCode::InternalError);
    }
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

std::optional<dns::server::FilterVersion> DNS::filter_version() const noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (!filter_updates_)
        return std::nullopt;
    return filter_updates_->current_version();
}

void DNS::request_stop_locked() noexcept
{
    if (state_ != State::Running && state_ != State::Stopping)
        return;

    if (filter_updates_)
        filter_updates_->close();
    state_ = State::Stopping;
    for (auto &thread : manager_threads_)
        thread.request_stop();
    for (auto &thread : worker_threads_)
        thread.request_stop();
    for (const auto &loop : worker_loops_)
        loop->request_stop();
}

void DNS::manager(std::stop_token stop_token) noexcept
{
    if (filter_updates_)
        filter_updates_->run(stop_token);
}
