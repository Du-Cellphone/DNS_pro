#include "DNS.h"

#include "WorkerSupervisor.h"

#include <cerrno>
#include <exception>
#include <new>
#include <system_error>
#include <utility>

namespace
{

dns::server::FilterUpdateResult filter_update_error(dns::server::FilterUpdateErrorCode code)
{
    return std::unexpected(dns::server::FilterUpdateError{code, std::nullopt});
}

DNSStartError make_start_error(DNSStartErrorCode code, DNSControlRole role = DNSControlRole::None, int error_number = 0) noexcept
{
    DNSStartError error;
    error.code         = code;
    error.role         = role;
    error.error_number = error_number;
    return error;
}

DNSStartError map_supervisor_start_error(const dns::server::SupervisorStartupError &error)
{
    DNSStartError mapped;
    mapped.role                 = DNSControlRole::Worker;
    mapped.worker_id            = error.worker_id;
    mapped.instance_id          = error.instance_id;
    mapped.worker_create_error  = error.create_error;
    mapped.worker_runtime_error = error.runtime_error;
    mapped.error_number         = error.error_number;

    using Code = dns::server::SupervisorStartupErrorCode;
    switch (error.code)
    {
        case Code::Cancelled:
            mapped.code = DNSStartErrorCode::Cancelled;
            break;
        case Code::WorkerCreateFailed:
            mapped.code = DNSStartErrorCode::WorkerCreateFailed;
            break;
        case Code::WorkerThreadStartFailed:
            mapped.code = DNSStartErrorCode::WorkerThreadCreationFailed;
            break;
        case Code::WorkerInitFailed:
        case Code::WorkerExitedBeforeReady:
            mapped.code = DNSStartErrorCode::WorkerRuntimeInitFailed;
            break;
        case Code::InvalidConfiguration:
        case Code::InstanceIdExhausted:
        case Code::InternalError:
            mapped.code = DNSStartErrorCode::SupervisorInitFailed;
            mapped.role = DNSControlRole::WorkerSupervisor;
            break;
    }
    return mapped;
}

DNSStartError map_supervisor_activation_error(const dns::server::SupervisorActivationError &error)
{
    if (error.code == dns::server::SupervisorActivationErrorCode::Cancelled)
        return make_start_error(DNSStartErrorCode::Cancelled);

    if (error.worker_id == dns::server::kInvalidWorkerId)
        return make_start_error(DNSStartErrorCode::SupervisorInitFailed, DNSControlRole::WorkerSupervisor);

    DNSStartError mapped = make_start_error(DNSStartErrorCode::WorkerRuntimeInitFailed, DNSControlRole::Worker);
    mapped.worker_id     = error.worker_id;
    mapped.instance_id   = error.instance_id;
    if (error.worker_result)
    {
        mapped.worker_runtime_error = error.worker_result->error;
        if (error.worker_result->error)
            mapped.error_number = error.worker_result->error->error_number;
    }
    return mapped;
}

DNSStartError cancelled_start_error()
{
    return make_start_error(DNSStartErrorCode::Cancelled);
}

DNSFatalError make_role_fatal(DNSFatalCode code, DNSControlRole role) noexcept
{
    DNSFatalError error;
    error.code = code;
    error.role = role;
    return error;
}

} // namespace

struct DNS::ControlPlaneState final : dns::server::FilterRunnerObserver, dns::server::SnapshotReclaimerObserver
{
    ControlPlaneState(dns::server::FilterSnapshot initial_snapshot, size_t worker_count)
        : publication(std::move(initial_snapshot), dns::server::FilterPublicationState::Config{.maximum_workers = worker_count})
    {
    }

    void reset(uint64_t value_attempt_id) noexcept
    {
        std::scoped_lock lock{mutex};
        attempt_id = value_attempt_id;
        coordinator_ready.reset();
        reclaimer_ready.reset();
        coordinator_result.reset();
        reclaimer_result.reset();
        supervisor_result.reset();
    }

    void report_reclaimer_ready(dns::server::SnapshotReclaimerReadyResult result) noexcept override
    {
        {
            std::scoped_lock lock{mutex};
            if (!reclaimer_ready)
                reclaimer_ready = result;
        }
        changed.notify_all();
    }

    void report_ready(dns::server::FilterRunnerReadyResult result) noexcept override
    {
        {
            std::scoped_lock lock{mutex};
            if (!coordinator_ready)
                coordinator_ready = result;
        }
        changed.notify_all();
    }

    void publish_coordinator_result(dns::server::FilterRunnerResult result) noexcept
    {
        {
            std::scoped_lock lock{mutex};
            if (!coordinator_result)
                coordinator_result = result;
        }
        changed.notify_all();
    }

    void publish_supervisor_result(dns::server::SupervisorRunResult result) noexcept
    {
        {
            std::scoped_lock lock{mutex};
            if (!supervisor_result)
                supervisor_result = std::move(result);
        }
        changed.notify_all();
    }

    void publish_reclaimer_result(dns::server::SnapshotReclaimerResult result) noexcept
    {
        {
            std::scoped_lock lock{mutex};
            if (!reclaimer_result)
                reclaimer_result = std::move(result);
        }
        changed.notify_all();
    }

    dns::server::FilterPublicationState                      publication;
    std::mutex                                               mutex;
    std::condition_variable_any                              changed;
    uint64_t                                                 attempt_id{0};
    std::optional<dns::server::FilterRunnerReadyResult>      coordinator_ready;
    std::optional<dns::server::SnapshotReclaimerReadyResult> reclaimer_ready;
    std::optional<dns::server::FilterRunnerResult>           coordinator_result;
    std::optional<dns::server::SnapshotReclaimerResult>      reclaimer_result;
    std::optional<dns::server::SupervisorRunResult>          supervisor_result;
};

struct DNS::FaultInjection final
{
    bool                                    coordinator_thread_failure{false};
    bool                                    coordinator_init_failure{false};
    bool                                    reclaimer_thread_failure{false};
    bool                                    reclaimer_init_failure{false};
    bool                                    supervisor_thread_failure{false};
    dns::server::WorkerSupervisorFaultHooks supervisor;

    std::mutex                  startup_pause_mutex;
    std::condition_variable_any startup_pause_changed;
    bool                        startup_pause_armed{false};
    bool                        startup_pause_reached{false};
};

DNS::DNS() = default;

DNS::~DNS()
{
    request_stop();
    if (join().code == DNSServiceExitCode::TeardownIncomplete)
    {
        // Returning from the destructor would release publication/worker
        // owners that a non-joined thread may still borrow. Fail fast and let
        // the process watchdog own the unrecoverable case instead of risking
        // a use-after-free during member destruction.
        std::terminate();
    }
}

bool DNS::init(const DNSConfig &config)
{
    {
        std::scoped_lock lock{lifecycle_mutex_};
        if (state_ != DNSLifecycleState::Empty || init_in_progress_)
            return false;
        init_in_progress_ = true;
    }

    const bool restart_config_valid = config.worker_failure_policy == WorkerFailurePolicy::FailService ||
                                      (config.restart_max_attempts != 0 && config.restart_initial_backoff.count() >= 0 &&
                                       config.restart_max_backoff >= config.restart_initial_backoff && config.restart_stability_window.count() >= 0);
    const bool valid = config.worker_count != 0 && dns::server::is_valid_upstream_config(config.upstream) && restart_config_valid;
    if (!valid)
    {
        std::scoped_lock lock{lifecycle_mutex_};
        init_in_progress_ = false;
        return false;
    }

    try
    {
        if (!dns::server::validate_filter_rule_set(config.blocked_domains))
        {
            std::scoped_lock lock{lifecycle_mutex_};
            init_in_progress_ = false;
            return false;
        }
        auto context = dns::server::build_filter_snapshot(config.blocked_domains, dns::server::kInitialFilterGeneration);
        if (!context)
        {
            std::scoped_lock lock{lifecycle_mutex_};
            init_in_progress_ = false;
            return false;
        }

        auto control        = std::make_unique<ControlPlaneState>(std::move(*context), config.worker_count);
        auto filter_updates = std::make_unique<dns::server::FilterUpdateController>(control->publication);
        auto cache          = std::make_unique<Cache::DNS_Cache>(config.cache_capacity, config.worker_count);
        auto faults         = std::make_unique<FaultInjection>();

        std::scoped_lock lock{lifecycle_mutex_};
        config_ = RuntimeConfig{
            .worker_count             = config.worker_count,
            .cache_capacity           = config.cache_capacity,
            .port                     = config.port,
            .runtime_updates_enabled  = config.runtime_updates_enabled,
            .worker_failure_policy    = config.worker_failure_policy,
            .restart_max_attempts     = config.restart_max_attempts,
            .restart_initial_backoff  = config.restart_initial_backoff,
            .restart_max_backoff      = config.restart_max_backoff,
            .restart_stability_window = config.restart_stability_window,
            .upstream                 = config.upstream,
        };
        health_ = DNSHealthSnapshot{
            .state                = DNSHealthState::Unavailable,
            .available_workers    = 0,
            .desired_workers      = config.worker_count,
            .restart_count        = 0,
            .effective_bound_port = std::nullopt,
            .filter_version       = filter_updates->current_version(),
            .last_error           = std::nullopt,
        };
        filter_updates_   = std::move(filter_updates);
        cache_            = std::move(cache);
        control_          = std::move(control);
        faults_           = std::move(faults);
        init_in_progress_ = false;
        state_            = DNSLifecycleState::Initialized;
        return true;
    }
    catch (...)
    {
        std::scoped_lock lock{lifecycle_mutex_};
        init_in_progress_ = false;
        return false;
    }
}

DNSStartResult DNS::start()
{
    // The accepted start attempt owns all startup resources until it either
    // returns success or completes rollback. request_stop() remains able to
    // cancel it, while join()/wait() cannot concurrently move those owners.
    std::unique_lock startup_owner{startup_mutex_};
    uint64_t         attempt_id{0};
    {
        std::scoped_lock lock{lifecycle_mutex_};
        if (state_ != DNSLifecycleState::Initialized || !filter_updates_ || !cache_ || !control_ || !faults_)
            return std::unexpected(make_start_error(DNSStartErrorCode::InvalidLifecycleState));

        state_      = DNSLifecycleState::Starting;
        stop_cause_ = StopCause::None;
        startup_error_.reset();
        fatal_error_.reset();
        update_admission_open_    = false;
        startup_stop_source_      = std::stop_source{};
        attempt_id                = ++startup_attempt_id_;
        health_.state             = DNSHealthState::Unavailable;
        health_.available_workers = 0;
        health_.effective_bound_port.reset();
        health_.last_error.reset();
    }
    control_->reset(attempt_id);

    const auto fail_start = [this](DNSStartError error) -> DNSStartResult
    {
        {
            std::scoped_lock lock{lifecycle_mutex_};
            if (stop_cause_ == StopCause::None)
            {
                stop_cause_    = StopCause::StartupFailure;
                startup_error_ = error;
            }
            if (state_ == DNSLifecycleState::Starting || state_ == DNSLifecycleState::Active)
                state_ = DNSLifecycleState::Stopping;
            update_admission_open_ = false;
            health_.state          = DNSHealthState::Unavailable;
            startup_stop_source_.request_stop();
            lifecycle_changed_.notify_all();
        }
        request_runtime_stop();
        static_cast<void>(finish_teardown(false));

        std::scoped_lock lock{lifecycle_mutex_};
        if (stop_cause_ == StopCause::Explicit)
            return std::unexpected(cancelled_start_error());
        return std::unexpected(startup_error_.value_or(std::move(error)));
    };

    try
    {
        dns::server::WorkerSupervisor::Config supervisor_config{
            .worker_count           = config_.worker_count,
            .requested_port         = config_.port,
            .cache                  = cache_.get(),
            .filter_publication     = &control_->publication,
            .upstream               = config_.upstream,
            .fault_hooks            = faults_->supervisor,
            .fatal_reporter_context = this,
            .fatal_reporter =
                [](void *context, size_t worker_id, uint64_t instance_id, const dns::server::WorkerRunResult &result) noexcept
            {
                auto         *service = static_cast<DNS *>(context);
                DNSFatalError error;
                error.code =
                    result.outcome == dns::server::WorkerRunOutcome::RequestedStop ? DNSFatalCode::UnexpectedWorkerStop : DNSFatalCode::WorkerExited;
                error.role         = DNSControlRole::Worker;
                error.worker_id    = worker_id;
                error.instance_id  = instance_id;
                error.worker_error = result.error;
                service->fail_service(std::move(error));
            },
        };
        auto             supervisor = std::make_unique<dns::server::WorkerSupervisor>(std::move(supervisor_config));
        std::scoped_lock lock{lifecycle_mutex_};
        supervisor_ = std::move(supervisor);
    }
    catch (const std::system_error &error)
    {
        return fail_start(make_start_error(DNSStartErrorCode::SupervisorInitFailed, DNSControlRole::WorkerSupervisor, error.code().value()));
    }
    catch (...)
    {
        return fail_start(make_start_error(DNSStartErrorCode::SupervisorInitFailed, DNSControlRole::WorkerSupervisor, ENOMEM));
    }

    if (config_.runtime_updates_enabled)
    {
        if (faults_->reclaimer_thread_failure)
        {
            return fail_start(make_start_error(DNSStartErrorCode::ReclaimerThreadCreationFailed, DNSControlRole::SnapshotReclaimer, EAGAIN));
        }
        try
        {
            std::jthread     reclaimer{[this, attempt_id](std::stop_token token) { reclaimer_main(token, attempt_id); }};
            std::scoped_lock lock{lifecycle_mutex_};
            reclaimer_thread_ = std::move(reclaimer);
        }
        catch (const std::system_error &error)
        {
            return fail_start(
                make_start_error(DNSStartErrorCode::ReclaimerThreadCreationFailed, DNSControlRole::SnapshotReclaimer, error.code().value()));
        }
        catch (...)
        {
            return fail_start(make_start_error(DNSStartErrorCode::ReclaimerThreadCreationFailed, DNSControlRole::SnapshotReclaimer, ENOMEM));
        }

        if (faults_->coordinator_thread_failure)
        {
            return fail_start(make_start_error(DNSStartErrorCode::CoordinatorThreadCreationFailed, DNSControlRole::FilterUpdateCoordinator, EAGAIN));
        }
        try
        {
            std::jthread     coordinator{[this, attempt_id](std::stop_token token) { coordinator_main(token, attempt_id); }};
            std::scoped_lock lock{lifecycle_mutex_};
            coordinator_thread_ = std::move(coordinator);
        }
        catch (const std::system_error &error)
        {
            return fail_start(
                make_start_error(DNSStartErrorCode::CoordinatorThreadCreationFailed, DNSControlRole::FilterUpdateCoordinator, error.code().value()));
        }
        catch (...)
        {
            return fail_start(make_start_error(DNSStartErrorCode::CoordinatorThreadCreationFailed, DNSControlRole::FilterUpdateCoordinator, ENOMEM));
        }
    }

    if (faults_->supervisor_thread_failure)
    {
        return fail_start(make_start_error(DNSStartErrorCode::SupervisorThreadCreationFailed, DNSControlRole::WorkerSupervisor, EAGAIN));
    }
    try
    {
        std::jthread     supervisor_thread{[this, attempt_id](std::stop_token token) { supervisor_main(token, attempt_id); }};
        std::scoped_lock lock{lifecycle_mutex_};
        supervisor_thread_ = std::move(supervisor_thread);
    }
    catch (const std::system_error &error)
    {
        return fail_start(
            make_start_error(DNSStartErrorCode::SupervisorThreadCreationFailed, DNSControlRole::WorkerSupervisor, error.code().value()));
    }
    catch (...)
    {
        return fail_start(make_start_error(DNSStartErrorCode::SupervisorThreadCreationFailed, DNSControlRole::WorkerSupervisor, ENOMEM));
    }

    const std::stop_token startup_token = startup_stop_source_.get_token();
    if (config_.runtime_updates_enabled)
    {
        bool reclaimer_ready{false};
        bool reclaimer_exited{false};
        {
            std::unique_lock lock{control_->mutex};
            control_->changed.wait(lock, startup_token,
                                   [this] { return control_->reclaimer_ready.has_value() || control_->reclaimer_result.has_value(); });
            reclaimer_ready  = control_->reclaimer_ready && control_->reclaimer_ready->code == dns::server::SnapshotReclaimerReadyCode::Ready;
            reclaimer_exited = control_->reclaimer_result.has_value();
        }
        if (!reclaimer_ready)
            return fail_start(make_start_error(startup_token.stop_requested() ? DNSStartErrorCode::Cancelled : DNSStartErrorCode::ReclaimerInitFailed,
                                               DNSControlRole::SnapshotReclaimer));
        if (reclaimer_exited)
            return fail_start(make_start_error(DNSStartErrorCode::ReclaimerInitFailed, DNSControlRole::SnapshotReclaimer));

        bool coordinator_ready{false};
        bool coordinator_exited{false};
        {
            std::unique_lock lock{control_->mutex};
            control_->changed.wait(lock, startup_token,
                                   [this] { return control_->coordinator_ready.has_value() || control_->coordinator_result.has_value(); });
            coordinator_ready  = control_->coordinator_ready && control_->coordinator_ready->code == dns::server::FilterRunnerReadyCode::Ready;
            coordinator_exited = control_->coordinator_result.has_value();
        }
        if (!coordinator_ready)
            return fail_start(
                make_start_error(startup_token.stop_requested() ? DNSStartErrorCode::Cancelled : DNSStartErrorCode::CoordinatorInitFailed,
                                 DNSControlRole::FilterUpdateCoordinator));
        if (coordinator_exited)
            return fail_start(make_start_error(DNSStartErrorCode::CoordinatorInitFailed, DNSControlRole::FilterUpdateCoordinator));
    }

    const auto supervisor_ready = supervisor_->wait_for_startup(startup_token);
    if (!supervisor_ready)
        return fail_start(map_supervisor_start_error(supervisor_ready.error()));

    bool activation_requested{false};
    {
        std::scoped_lock lock{lifecycle_mutex_};
        if (state_ == DNSLifecycleState::Starting && stop_cause_ == StopCause::None && startup_attempt_id_ == attempt_id)
            activation_requested = supervisor_->request_activation();
    }
    if (!activation_requested)
        return fail_start(cancelled_start_error());

    const auto activated = supervisor_->wait_for_activation(startup_token);
    if (!activated)
        return fail_start(map_supervisor_activation_error(activated.error()));

    bool startup_pause_cancelled{false};
    {
        std::unique_lock pause_lock{faults_->startup_pause_mutex};
        if (faults_->startup_pause_armed)
        {
            faults_->startup_pause_reached = true;
            faults_->startup_pause_changed.notify_all();
            const bool released_by_test_stop =
                faults_->startup_pause_changed.wait(pause_lock, startup_token, [this] { return !faults_->startup_pause_armed; });
            if (!released_by_test_stop)
                startup_pause_cancelled = true;
        }
    }
    if (startup_pause_cancelled)
        return fail_start(cancelled_start_error());

    bool                         startup_committed{false};
    std::optional<DNSStartError> commit_error;
    const auto                   commit_startup = [this, attempt_id, &supervisor_ready, &startup_committed, &commit_error]() noexcept
    {
        if (state_ == DNSLifecycleState::Starting && stop_cause_ == StopCause::None && startup_attempt_id_ == attempt_id)
        {
            // Workers have acknowledged the first gate but remain blocked on
            // the data-plane gate. Commit service visibility first, then
            // release that gate while the lifecycle decision is stable.
            state_                       = DNSLifecycleState::Active;
            health_.state                = DNSHealthState::Healthy;
            health_.available_workers    = config_.worker_count;
            health_.effective_bound_port = supervisor_ready->bound_port;
            health_.filter_version       = filter_updates_->current_version();
            const auto released          = supervisor_->release_data_plane();
            if (released)
            {
                update_admission_open_ = config_.runtime_updates_enabled;
                startup_committed      = true;
            }
            else
            {
                commit_error = map_supervisor_activation_error(released.error());
                // No reader can observe this tentative commit while the
                // lifecycle mutex is held. Restore Starting and let the
                // startup owner perform the ordinary rollback.
                state_                    = DNSLifecycleState::Starting;
                health_.state             = DNSHealthState::Unavailable;
                health_.available_workers = 0;
                health_.effective_bound_port.reset();
                update_admission_open_ = false;
            }
        }
    };
    if (config_.runtime_updates_enabled)
    {
        // A publication on coordinator_result is the coordinator's exit
        // linearization point. Holding both locks makes the required-role
        // liveness check part of the same all-or-nothing Active commit.
        std::scoped_lock lock{lifecycle_mutex_, control_->mutex};
        if (!control_->coordinator_result && !control_->reclaimer_result)
            commit_startup();
        else if (control_->reclaimer_result)
            commit_error = make_start_error(DNSStartErrorCode::ReclaimerInitFailed, DNSControlRole::SnapshotReclaimer);
        else
            commit_error = make_start_error(DNSStartErrorCode::CoordinatorInitFailed, DNSControlRole::FilterUpdateCoordinator);
    }
    else
    {
        std::scoped_lock lock{lifecycle_mutex_};
        commit_startup();
    }
    lifecycle_changed_.notify_all();
    if (!startup_committed)
        return fail_start(commit_error.value_or(cancelled_start_error()));
    return DNSStartInfo{supervisor_ready->bound_port, supervisor_ready->worker_count, attempt_id};
}

void DNS::request_stop() noexcept
{
    bool                                                 stop_runtime{false};
    bool                                                 abandon_initialized{false};
    std::unique_ptr<dns::server::FilterUpdateController> initialized_filter;
    std::unique_ptr<Cache::DNS_Cache>                    initialized_cache;
    std::unique_ptr<ControlPlaneState>                   initialized_control;
    std::unique_ptr<FaultInjection>                      initialized_faults;
    {
        std::scoped_lock lock{lifecycle_mutex_};
        if (state_ == DNSLifecycleState::Empty || state_ == DNSLifecycleState::Stopped || state_ == DNSLifecycleState::Failed)
            return;
        if (state_ == DNSLifecycleState::Initialized)
        {
            stop_cause_               = StopCause::Explicit;
            state_                    = DNSLifecycleState::Stopped;
            update_admission_open_    = false;
            health_.state             = DNSHealthState::Unavailable;
            health_.available_workers = 0;
            initialized_filter        = std::move(filter_updates_);
            initialized_cache         = std::move(cache_);
            initialized_control       = std::move(control_);
            initialized_faults        = std::move(faults_);
            abandon_initialized       = true;
            lifecycle_changed_.notify_all();
        }
        else
        {
            if (stop_cause_ == StopCause::None)
                stop_cause_ = StopCause::Explicit;
            if (state_ == DNSLifecycleState::Starting || state_ == DNSLifecycleState::Active)
                state_ = DNSLifecycleState::Stopping;
            update_admission_open_    = false;
            health_.state             = DNSHealthState::Unavailable;
            health_.available_workers = 0;
            startup_stop_source_.request_stop();
            stop_runtime = true;
            lifecycle_changed_.notify_all();
        }
    }
    if (abandon_initialized)
    {
        initialized_filter.reset();
        initialized_control.reset();
        initialized_faults.reset();
        initialized_cache.reset();
        return;
    }
    if (stop_runtime)
        request_runtime_stop();
}

DNSServiceExitResult DNS::join() noexcept
{
    request_stop();
    std::scoped_lock startup_owner{startup_mutex_};
    return finish_teardown(false);
}

DNSServiceExitResult DNS::wait() noexcept
{
    {
        std::unique_lock lock{lifecycle_mutex_};
        lifecycle_changed_.wait(lock,
                                [this]
                                {
                                    return state_ == DNSLifecycleState::Empty || state_ == DNSLifecycleState::Initialized ||
                                           state_ == DNSLifecycleState::Stopping || state_ == DNSLifecycleState::Stopped ||
                                           state_ == DNSLifecycleState::Failed;
                                });
        if (state_ == DNSLifecycleState::Empty)
            return exit_result_locked();
    }
    std::scoped_lock startup_owner{startup_mutex_};
    return finish_teardown(false);
}

dns::server::FilterUpdateResult DNS::replace_blocked_domains(std::vector<std::string> rules)
{
    try
    {
        dns::server::FilterUpdateFuture future;
        {
            std::scoped_lock lock{lifecycle_mutex_};
            if (state_ == DNSLifecycleState::Stopping || state_ == DNSLifecycleState::Stopped || state_ == DNSLifecycleState::Failed)
                return filter_update_error(dns::server::FilterUpdateErrorCode::ShuttingDown);
            if (state_ != DNSLifecycleState::Active)
                return filter_update_error(dns::server::FilterUpdateErrorCode::ServiceNotRunning);
            if (!config_.runtime_updates_enabled)
                return filter_update_error(dns::server::FilterUpdateErrorCode::ControlPlaneDisabled);
            if (!update_admission_open_)
                return filter_update_error(dns::server::FilterUpdateErrorCode::ServiceNotRunning);
            if (!filter_updates_)
                return filter_update_error(dns::server::FilterUpdateErrorCode::InternalError);
            future = filter_updates_->submit_replace(std::move(rules));
        }

        auto result = future.get();
        if (result)
        {
            std::scoped_lock lock{lifecycle_mutex_};
            if (!health_.filter_version || result->generation > health_.filter_version->generation)
                health_.filter_version = *result;
        }
        return result;
    }
    catch (...)
    {
        return filter_update_error(dns::server::FilterUpdateErrorCode::InternalError);
    }
}

bool DNS::is_running() const noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    return state_ == DNSLifecycleState::Active;
}

DNSLifecycleState DNS::lifecycle_state() const noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    return state_;
}

DNSHealthSnapshot DNS::health() const noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    return health_;
}

std::optional<uint16_t> DNS::bound_port() const noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    return health_.effective_bound_port;
}

std::optional<dns::server::FilterVersion> DNS::filter_version() const noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (filter_updates_)
        return filter_updates_->current_version();
    return health_.filter_version;
}

void DNS::reclaimer_main(std::stop_token stop_token, uint64_t attempt_id) noexcept
{
    if (faults_ && faults_->reclaimer_init_failure)
    {
        control_->report_reclaimer_ready(dns::server::SnapshotReclaimerReadyResult{dns::server::SnapshotReclaimerReadyCode::AlreadyRunning});
        control_->publish_reclaimer_result(dns::server::SnapshotReclaimerResult{dns::server::SnapshotReclaimerExitCode::FatalExit, nullptr});
        return;
    }

    dns::server::SnapshotReclaimerResult result;
    try
    {
        result = control_->publication.run_reclaimer(stop_token, control_.get());
    }
    catch (...)
    {
        result = dns::server::SnapshotReclaimerResult{dns::server::SnapshotReclaimerExitCode::FatalExit, nullptr};
    }
    const dns::server::SnapshotReclaimerExitCode exit_code  = result.code;
    auto                                         diagnostic = result.diagnostic;
    control_->publish_reclaimer_result(std::move(result));

    bool startup_failure{false};
    bool runtime_failure{false};
    {
        std::scoped_lock lock{lifecycle_mutex_};
        const bool       expected_stop = startup_stop_source_.stop_requested() || state_ == DNSLifecycleState::Stopping ||
                                   state_ == DNSLifecycleState::Stopped || state_ == DNSLifecycleState::Failed;
        if (!expected_stop && startup_attempt_id_ == attempt_id)
        {
            if (state_ == DNSLifecycleState::Starting)
            {
                if (stop_cause_ == StopCause::None)
                {
                    stop_cause_    = StopCause::StartupFailure;
                    startup_error_ = make_start_error(DNSStartErrorCode::ReclaimerInitFailed, DNSControlRole::SnapshotReclaimer);
                }
                state_ = DNSLifecycleState::Stopping;
                startup_stop_source_.request_stop();
                startup_failure = true;
            }
            else if (state_ == DNSLifecycleState::Active)
            {
                DNSFatalError error =
                    make_role_fatal(exit_code == dns::server::SnapshotReclaimerExitCode::GracePeriodStalled ? DNSFatalCode::GracePeriodStalled
                                                                                                            : DNSFatalCode::ReclaimerExited,
                                    DNSControlRole::SnapshotReclaimer);
                error.grace_diagnostic = std::move(diagnostic);
                runtime_failure        = accept_fatal_locked(std::move(error));
            }
        }
        lifecycle_changed_.notify_all();
    }
    if (startup_failure || runtime_failure)
        request_runtime_stop();
}

void DNS::coordinator_main(std::stop_token stop_token, uint64_t attempt_id) noexcept
{
    if (faults_ && faults_->coordinator_init_failure)
    {
        control_->report_ready(dns::server::FilterRunnerReadyResult{dns::server::FilterRunnerReadyCode::AlreadyRunning});
        control_->publish_coordinator_result(dns::server::FilterRunnerResult{dns::server::FilterRunnerExitCode::FatalExit});
        return;
    }

    dns::server::FilterRunnerResult result{dns::server::FilterRunnerExitCode::FatalExit};
    try
    {
        result = filter_updates_->run(stop_token, control_.get());
    }
    catch (...)
    {
        result.code = dns::server::FilterRunnerExitCode::FatalExit;
    }
    control_->publish_coordinator_result(result);

    bool startup_failure{false};
    bool runtime_failure{false};
    {
        std::scoped_lock lock{lifecycle_mutex_};
        const bool expected_stop = stop_token.stop_requested() || startup_stop_source_.stop_requested() || state_ == DNSLifecycleState::Stopping ||
                                   state_ == DNSLifecycleState::Stopped || state_ == DNSLifecycleState::Failed;
        if (!expected_stop && startup_attempt_id_ == attempt_id)
        {
            if (state_ == DNSLifecycleState::Starting)
            {
                if (stop_cause_ == StopCause::None)
                {
                    stop_cause_    = StopCause::StartupFailure;
                    startup_error_ = make_start_error(DNSStartErrorCode::CoordinatorInitFailed, DNSControlRole::FilterUpdateCoordinator);
                }
                state_ = DNSLifecycleState::Stopping;
                startup_stop_source_.request_stop();
                startup_failure = true;
            }
            else if (state_ == DNSLifecycleState::Active)
            {
                runtime_failure = accept_fatal_locked(make_role_fatal(DNSFatalCode::CoordinatorExited, DNSControlRole::FilterUpdateCoordinator));
            }
        }
        lifecycle_changed_.notify_all();
    }
    if (startup_failure)
        request_runtime_stop();
    if (runtime_failure)
        request_runtime_stop();
}

void DNS::supervisor_main(std::stop_token stop_token, uint64_t attempt_id) noexcept
{
    dns::server::SupervisorRunResult result;
    try
    {
        result = supervisor_->run(stop_token);
    }
    catch (...)
    {
        result.outcome    = dns::server::SupervisorRunOutcome::FatalExit;
        result.error_code = dns::server::SupervisorRunErrorCode::InternalError;
    }
    control_->publish_supervisor_result(result);

    bool startup_failure{false};
    bool runtime_failure{false};
    {
        std::scoped_lock lock{lifecycle_mutex_};
        const bool expected_stop = stop_token.stop_requested() || startup_stop_source_.stop_requested() || state_ == DNSLifecycleState::Stopping ||
                                   state_ == DNSLifecycleState::Stopped || state_ == DNSLifecycleState::Failed;
        if (!expected_stop && startup_attempt_id_ == attempt_id)
        {
            if (state_ == DNSLifecycleState::Starting)
            {
                if (stop_cause_ == StopCause::None)
                {
                    stop_cause_ = StopCause::StartupFailure;
                    if (result.startup_error)
                    {
                        startup_error_ = map_supervisor_start_error(*result.startup_error);
                    }
                    else if (result.worker_id != dns::server::kInvalidWorkerId)
                    {
                        DNSStartError mapped =
                            make_start_error(DNSStartErrorCode::WorkerRuntimeInitFailed, DNSControlRole::Worker, result.error_number);
                        mapped.worker_id            = result.worker_id;
                        mapped.instance_id          = result.instance_id;
                        mapped.worker_runtime_error = result.worker_result ? result.worker_result->error : std::nullopt;
                        startup_error_              = std::move(mapped);
                    }
                    else
                    {
                        startup_error_ = make_start_error(DNSStartErrorCode::SupervisorInitFailed, DNSControlRole::WorkerSupervisor);
                    }
                }
                state_ = DNSLifecycleState::Stopping;
                startup_stop_source_.request_stop();
                startup_failure = true;
            }
            else if (state_ == DNSLifecycleState::Active)
            {
                runtime_failure = accept_fatal_locked(make_role_fatal(DNSFatalCode::SupervisorExited, DNSControlRole::WorkerSupervisor));
            }
        }
        lifecycle_changed_.notify_all();
    }
    if (startup_failure)
        request_runtime_stop();
    if (runtime_failure)
        request_runtime_stop();
}

bool DNS::accept_fatal_locked(DNSFatalError error) noexcept
{
    // Initial-start failures are classified by the start-attempt owner and
    // role result channels. The runtime fatal path opens only after Active.
    if (state_ != DNSLifecycleState::Active || stop_cause_ != StopCause::None)
        return false;

    stop_cause_               = StopCause::Fatal;
    fatal_error_              = error;
    state_                    = DNSLifecycleState::Stopping;
    update_admission_open_    = false;
    health_.state             = DNSHealthState::Unavailable;
    health_.available_workers = 0;
    health_.last_error        = std::move(error);
    startup_stop_source_.request_stop();
    return true;
}

void DNS::fail_service(DNSFatalError error) noexcept
{
    bool accepted{false};
    {
        std::scoped_lock lock{lifecycle_mutex_};
        accepted = accept_fatal_locked(std::move(error));
        lifecycle_changed_.notify_all();
    }
    if (accepted)
        request_runtime_stop();
}

void DNS::request_runtime_stop() noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    startup_stop_source_.request_stop();
    update_admission_open_ = false;
    if (filter_updates_)
        filter_updates_->seal();
    if (supervisor_)
        supervisor_->request_stop();
    if (supervisor_thread_.joinable())
        supervisor_thread_.request_stop();
}

DNSServiceExitResult DNS::finish_teardown(bool request_explicit_stop) noexcept
{
    if (request_explicit_stop)
        request_stop();

    std::scoped_lock join_lock{join_mutex_};
    {
        std::scoped_lock lock{lifecycle_mutex_};
        if (state_ == DNSLifecycleState::Empty || state_ == DNSLifecycleState::Initialized || state_ == DNSLifecycleState::Stopped ||
            state_ == DNSLifecycleState::Failed)
            return exit_result_locked();
    }

    request_runtime_stop();

    const auto teardown_incomplete = [this]() noexcept
    {
        std::scoped_lock lock{lifecycle_mutex_};
        state_                    = DNSLifecycleState::Stopping;
        health_.state             = DNSHealthState::Unavailable;
        health_.available_workers = 0;
        lifecycle_changed_.notify_all();
        return DNSServiceExitResult{DNSServiceExitCode::TeardownIncomplete, startup_error_, fatal_error_};
    };

    // C is drained first. join_and_reset() releases every worker-local owner
    // before it publishes quiesced_through_instance_id, allowing B (or an
    // emergency successor) to finish any committed publication.
    std::jthread supervisor_thread;
    {
        std::scoped_lock lock{lifecycle_mutex_};
        supervisor_thread = std::move(supervisor_thread_);
    }
    if (supervisor_thread.joinable())
    {
        supervisor_thread.request_stop();
        try
        {
            supervisor_thread.join();
        }
        catch (...)
        {
        }
    }
    if (supervisor_thread.joinable())
    {
        {
            std::scoped_lock lock{lifecycle_mutex_};
            supervisor_thread_ = std::move(supervisor_thread);
        }
        return teardown_incomplete();
    }
    if (supervisor_ && !supervisor_->emergency_join_all())
        return teardown_incomplete();

    bool reclaimer_available{false};
    {
        std::scoped_lock lock{lifecycle_mutex_};
        reclaimer_available = reclaimer_thread_.joinable();
    }
    auto join_failed_reclaimer = [this, &reclaimer_available]() noexcept -> bool
    {
        std::jthread reclaimer;
        {
            std::scoped_lock lock{lifecycle_mutex_};
            reclaimer = std::move(reclaimer_thread_);
        }
        if (reclaimer.joinable())
        {
            try
            {
                reclaimer.join();
            }
            catch (...)
            {
            }
        }
        if (reclaimer.joinable())
        {
            std::scoped_lock lock{lifecycle_mutex_};
            reclaimer_thread_ = std::move(reclaimer);
            return false;
        }
        reclaimer_available = false;
        return control_ == nullptr || control_->publication.emergency_reclaim_converged();
    };

    bool reclaimer_exited{false};
    if (control_ != nullptr)
    {
        std::scoped_lock lock{control_->mutex};
        reclaimer_exited = control_->reclaimer_result.has_value();
    }
    if (reclaimer_exited && !join_failed_reclaimer())
        return teardown_incomplete();

    if (config_.runtime_updates_enabled && filter_updates_ != nullptr)
    {
        // This wakes A without stopping its thread. If A is still waiting for
        // a committed cohort, B remains live and the worker quiescence above
        // lets that wait complete first.
        filter_updates_->request_terminal_detach();

        bool coordinator_exists{false};
        {
            std::scoped_lock lock{lifecycle_mutex_};
            coordinator_exists = coordinator_thread_.joinable();
        }
        bool coordinator_finished = !coordinator_exists;
        while (!coordinator_finished)
        {
            bool observed_reclaimer_exit{false};
            {
                std::unique_lock lock{control_->mutex};
                control_->changed.wait(
                    lock, [this, &reclaimer_available]
                    { return control_->coordinator_result.has_value() || (reclaimer_available && control_->reclaimer_result.has_value()); });
                coordinator_finished    = control_->coordinator_result.has_value();
                observed_reclaimer_exit = control_->reclaimer_result.has_value();
            }
            if (!coordinator_finished && observed_reclaimer_exit && reclaimer_available)
            {
                if (!join_failed_reclaimer())
                    return teardown_incomplete();
            }
        }
    }

    std::jthread coordinator;
    {
        std::scoped_lock lock{lifecycle_mutex_};
        coordinator = std::move(coordinator_thread_);
    }
    if (coordinator.joinable())
    {
        try
        {
            coordinator.join();
        }
        catch (...)
        {
        }
    }
    if (coordinator.joinable())
    {
        {
            std::scoped_lock lock{lifecycle_mutex_};
            coordinator_thread_ = std::move(coordinator);
        }
        return teardown_incomplete();
    }

    if (filter_updates_ != nullptr)
    {
        auto successor_result = filter_updates_->complete_committed_by_successor();
        if (successor_result != dns::server::FilterSuccessorCompletionResult::Completed)
        {
            // A has been joined, so the stable journal can be taken over. Only
            // an explicit ReclaimerUnavailable result proves that joining B
            // cannot block; an internal wait failure must retain all owners.
            if (successor_result != dns::server::FilterSuccessorCompletionResult::ReclaimerUnavailable || !reclaimer_available ||
                !join_failed_reclaimer())
                return teardown_incomplete();
            successor_result = filter_updates_->complete_committed_by_successor();
            if (successor_result != dns::server::FilterSuccessorCompletionResult::Completed)
                return teardown_incomplete();
        }
    }

    if (control_ != nullptr)
    {
        control_->publication.seal_publication();
        if (!control_->publication.detach_terminal_snapshot())
            return teardown_incomplete();
    }

    if (reclaimer_available)
    {
        control_->publication.request_reclaimer_shutdown();
        std::jthread reclaimer;
        {
            std::scoped_lock lock{lifecycle_mutex_};
            reclaimer = std::move(reclaimer_thread_);
        }
        if (reclaimer.joinable())
        {
            try
            {
                reclaimer.join();
            }
            catch (...)
            {
            }
        }
        if (reclaimer.joinable())
        {
            {
                std::scoped_lock lock{lifecycle_mutex_};
                reclaimer_thread_ = std::move(reclaimer);
            }
            return teardown_incomplete();
        }
        reclaimer_available = false;
        if (!control_->publication.emergency_reclaim_converged())
            return teardown_incomplete();
    }
    else if (control_ != nullptr && !control_->publication.emergency_reclaim_converged())
    {
        return teardown_incomplete();
    }

    if (filter_updates_ != nullptr && filter_updates_->complete_committed_by_successor() != dns::server::FilterSuccessorCompletionResult::Completed)
        return teardown_incomplete();

    std::unique_ptr<Cache::DNS_Cache>                    cache;
    std::unique_ptr<ControlPlaneState>                   control;
    std::unique_ptr<FaultInjection>                      faults;
    std::unique_ptr<dns::server::FilterUpdateController> filter_updates;
    std::unique_ptr<dns::server::WorkerSupervisor>       supervisor;
    DNSServiceExitResult                                 exit_result;
    {
        std::scoped_lock lock{lifecycle_mutex_};
        if (filter_updates_)
            health_.filter_version = filter_updates_->current_version();
        supervisor     = std::move(supervisor_);
        filter_updates = std::move(filter_updates_);
        cache          = std::move(cache_);
        control        = std::move(control_);
        faults         = std::move(faults_);

        health_.state             = DNSHealthState::Unavailable;
        health_.available_workers = 0;
        state_                    = stop_cause_ == StopCause::Explicit ? DNSLifecycleState::Stopped : DNSLifecycleState::Failed;
        lifecycle_changed_.notify_all();
        exit_result = exit_result_locked();
    }

    // B no longer scans epochs, so the stable registry can now be destroyed.
    // The controller still borrows ControlPlaneState and therefore dies first.
    supervisor.reset();
    filter_updates.reset();
    control.reset();
    faults.reset();
    cache.reset();
    return exit_result;
}

DNSServiceExitResult DNS::exit_result_locked() const noexcept
{
    switch (stop_cause_)
    {
        case StopCause::Explicit:
            return DNSServiceExitResult{DNSServiceExitCode::ExplicitStop, std::nullopt, std::nullopt};
        case StopCause::StartupFailure:
            return DNSServiceExitResult{DNSServiceExitCode::StartupFailure, startup_error_, std::nullopt};
        case StopCause::Fatal:
            return DNSServiceExitResult{DNSServiceExitCode::Fatal, std::nullopt, fatal_error_};
        case StopCause::None:
            return DNSServiceExitResult{};
    }
    return DNSServiceExitResult{};
}

void DNS::inject_coordinator_thread_failure_for_test() noexcept
{
    if (faults_)
        faults_->coordinator_thread_failure = true;
}

void DNS::inject_coordinator_init_failure_for_test() noexcept
{
    if (faults_)
        faults_->coordinator_init_failure = true;
}

void DNS::inject_coordinator_runtime_failure_for_test() noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (filter_updates_)
        filter_updates_->request_terminal_detach();
}

void DNS::inject_coordinator_postcommit_failure_for_test() noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (filter_updates_)
        filter_updates_->inject_postcommit_failure_for_testing();
}

void DNS::inject_reclaimer_thread_failure_for_test() noexcept
{
    if (faults_)
        faults_->reclaimer_thread_failure = true;
}

void DNS::inject_reclaimer_init_failure_for_test() noexcept
{
    if (faults_)
        faults_->reclaimer_init_failure = true;
}

void DNS::inject_reclaimer_runtime_failure_for_test() noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (control_)
        control_->publication.inject_reclaimer_failure_for_testing();
}

void DNS::inject_reclaimer_postcommit_failure_for_test() noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (control_)
        control_->publication.inject_reclaimer_failure_after_next_commit_for_testing();
}

void DNS::inject_supervisor_thread_failure_for_test() noexcept
{
    if (faults_)
        faults_->supervisor_thread_failure = true;
}

void DNS::inject_supervisor_runtime_failure_for_test() noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (supervisor_)
        supervisor_->inject_abrupt_exit_for_testing();
}

void DNS::inject_supervisor_postcommit_failure_for_test() noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (supervisor_)
        supervisor_->inject_abrupt_exit_after_next_publication_for_testing();
}

void DNS::inject_worker_create_failure_for_test(size_t worker_id, dns::server::WorkerInitStep step, int error_number) noexcept
{
    if (!faults_)
        return;
    faults_->supervisor.create_failure_worker = worker_id;
    faults_->supervisor.create_failure_step   = step;
    faults_->supervisor.create_failure_error  = error_number;
}

void DNS::inject_worker_runtime_init_failure_for_test(size_t worker_id) noexcept
{
    if (faults_)
        faults_->supervisor.runtime_init_failure_worker = worker_id;
}

void DNS::inject_worker_thread_failure_for_test(size_t worker_id) noexcept
{
    if (!faults_)
        return;
    faults_->supervisor.thread_failure_worker = worker_id;
    faults_->supervisor.thread_failure_error  = EAGAIN;
}

void DNS::inject_worker_unexpected_stop_for_test(size_t worker_id) noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (supervisor_)
        supervisor_->inject_worker_unexpected_stop_for_testing(worker_id);
}

bool DNS::inject_worker_precommit_failure_for_test(size_t worker_id) noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    return supervisor_ && supervisor_->inject_worker_precommit_failure_for_testing(worker_id);
}

void DNS::inject_teardown_incomplete_once_for_test() noexcept
{
    std::scoped_lock lock{lifecycle_mutex_};
    if (supervisor_)
        supervisor_->inject_emergency_join_failure_once_for_testing();
}

void DNS::arm_startup_pause_for_test() noexcept
{
    std::scoped_lock lifecycle_lock{lifecycle_mutex_};
    if (!faults_ || state_ != DNSLifecycleState::Initialized)
        return;

    std::scoped_lock pause_lock{faults_->startup_pause_mutex};
    faults_->startup_pause_armed   = true;
    faults_->startup_pause_reached = false;
}

void DNS::wait_for_startup_pause_for_test()
{
    FaultInjection *faults{nullptr};
    {
        std::scoped_lock lock{lifecycle_mutex_};
        faults = faults_.get();
    }
    if (faults == nullptr)
        return;

    std::unique_lock lock{faults->startup_pause_mutex};
    faults->startup_pause_changed.wait(lock, [faults] { return faults->startup_pause_reached; });
}

void DNS::release_startup_pause_for_test() noexcept
{
    std::scoped_lock lifecycle_lock{lifecycle_mutex_};
    if (!faults_)
        return;

    {
        std::scoped_lock pause_lock{faults_->startup_pause_mutex};
        faults_->startup_pause_armed = false;
    }
    faults_->startup_pause_changed.notify_all();
}
