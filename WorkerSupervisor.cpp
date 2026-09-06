#include "WorkerSupervisor.h"

#include <algorithm>
#include <cerrno>
#include <exception>
#include <new>
#include <system_error>
#include <utility>

namespace dns::server
{
namespace
{

struct InjectedSupervisorFailure final
{
};

using Clock = std::chrono::steady_clock;

Clock::time_point deadline_after(Clock::time_point now, std::chrono::milliseconds delay) noexcept
{
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::time_point::max() - now);
    return delay >= remaining ? Clock::time_point::max() : now + delay;
}

std::chrono::milliseconds doubled_backoff(std::chrono::milliseconds current, std::chrono::milliseconds maximum) noexcept
{
    return current >= maximum - current ? maximum : current + current;
}

WorkerFailure creation_failure(const SupervisorStartupError &error) noexcept
{
    WorkerFailure failure;
    failure.code          = error.code == SupervisorStartupErrorCode::InstanceIdExhausted       ? WorkerFailureCode::InstanceIdExhausted
                            : error.code == SupervisorStartupErrorCode::WorkerThreadStartFailed ? WorkerFailureCode::ThreadStartFailed
                                                                                                : WorkerFailureCode::CreateFailed;
    failure.worker_id     = error.worker_id;
    failure.instance_id   = error.instance_id;
    failure.error_number  = error.error_number;
    failure.create_error  = error.create_error;
    failure.runtime_error = error.runtime_error;
    return failure;
}

int configured_error_or(int configured, int fallback) noexcept
{
    return configured != 0 ? configured : fallback;
}

SupervisorStartupError cancelled_startup() noexcept
{
    return SupervisorStartupError{.code = SupervisorStartupErrorCode::Cancelled, .create_error = std::nullopt, .runtime_error = std::nullopt};
}

SupervisorActivationError cancelled_activation() noexcept
{
    return SupervisorActivationError{.code = SupervisorActivationErrorCode::Cancelled, .worker_result = std::nullopt};
}

SupervisorRunResult requested_stop_result() noexcept
{
    return SupervisorRunResult{
        .outcome       = SupervisorRunOutcome::RequestedStop,
        .error_code    = SupervisorRunErrorCode::None,
        .startup_error = std::nullopt,
        .worker_result = std::nullopt,
    };
}

SupervisorRunResult startup_failure_result(const SupervisorStartupError &error) noexcept
{
    return SupervisorRunResult{
        .outcome       = SupervisorRunOutcome::StartupFailure,
        .error_code    = SupervisorRunErrorCode::None,
        .worker_id     = error.worker_id,
        .instance_id   = error.instance_id,
        .error_number  = error.error_number,
        .startup_error = error,
        .worker_result = std::nullopt,
    };
}

} // namespace

class WorkerRecordObserver final : public WorkerRunObserver
{
public:
    WorkerRecordObserver(WorkerSupervisor &supervisor, WorkerRecord &record) noexcept
        : supervisor_(supervisor)
        , record_(record)
    {
    }

    void bind(uint64_t instance_id) noexcept { instance_id_ = instance_id; }

    void report_ready(WorkerReadyResult result) noexcept override { supervisor_.report_worker_ready(record_, instance_id_, std::move(result)); }

    WorkerRunObserver::GateAction await_activation(std::stop_token stop_token) noexcept override
    {
        return supervisor_.await_worker_activation(record_, instance_id_, stop_token);
    }

    void report_activated() noexcept override { supervisor_.report_worker_activated(record_, instance_id_); }

    WorkerRunObserver::GateAction await_data_plane(std::stop_token stop_token) noexcept override
    {
        return supervisor_.await_worker_data_plane(record_, instance_id_, stop_token);
    }

    void report_filter_progress() noexcept override { supervisor_.report_worker_filter_progress(record_, instance_id_); }

private:
    WorkerSupervisor &supervisor_;
    WorkerRecord     &record_;
    uint64_t          instance_id_{0};
};

WorkerRecord::WorkerRecord(size_t worker_id)
    : worker_id_(worker_id)
{
}

WorkerRecord::~WorkerRecord()
{
    instance_stop_source_.request_stop();
    if (current_instance_)
        current_instance_->request_stop();
    if (current_thread_.joinable())
    {
        current_thread_.request_stop();
        try
        {
            if (current_thread_.get_id() == std::this_thread::get_id())
                std::terminate();
            current_thread_.join();
        }
        catch (...)
        {
            // Destroying observer_/current_instance_ while the worker could
            // still call them is worse than terminating at this invariant
            // boundary. Normal and emergency teardown join before destruction.
            std::terminate();
        }
    }
    current_instance_.reset();
    observer_.reset();
}

WorkerSupervisor::WorkerSupervisor(Config config)
    : config_(std::move(config))
{
    records_.reserve(config_.worker_count);
    for (size_t worker_id = 0; worker_id < config_.worker_count; ++worker_id)
    {
        auto record       = std::unique_ptr<WorkerRecord>{new WorkerRecord{worker_id}};
        record->observer_ = std::make_unique<WorkerRecordObserver>(*this, *record);
        records_.push_back(std::move(record));
    }
    if (config_.filter_publication != nullptr)
    {
        published_generation_ = config_.filter_publication->current_generation();
        config_.filter_publication->set_publication_sink(this);
    }
}

WorkerSupervisor::~WorkerSupervisor()
{
    request_stop();
    {
        std::unique_lock lock{mutex_};
        wakeup_.wait(lock, [this] { return !run_active_.load(std::memory_order_acquire); });
    }
    static_cast<void>(emergency_join_all());
    if (config_.filter_publication != nullptr)
        config_.filter_publication->set_publication_sink(nullptr);
    // Destroy records while mutex_/wakeup_ and every callback target are still
    // alive. WorkerRecord's destructor is the final stop/join safety net if an
    // emergency join could not prove completion.
    records_.clear();
}

SupervisorRunResult WorkerSupervisor::run(std::stop_token stop_token)
{
    {
        std::scoped_lock lock{mutex_};
        if (run_started_)
        {
            return SupervisorRunResult{
                .outcome       = SupervisorRunOutcome::FatalExit,
                .error_code    = SupervisorRunErrorCode::AlreadyRunning,
                .startup_error = std::nullopt,
                .worker_result = std::nullopt,
            };
        }
        run_started_ = true;
        run_active_.store(true, std::memory_order_release);
    }

    std::stop_callback forward_stop{stop_token, [this] { request_stop(); }};
    try
    {
        SupervisorRunResult result = run_impl(stop_token);
        finish_run();
        return result;
    }
    catch (...)
    {
        publish_abrupt_failure();
        request_all_worker_stops();
        finish_run();
        throw;
    }
}

SupervisorRunResult WorkerSupervisor::run_impl(std::stop_token)
{
    bool initially_stopped = false;
    {
        std::scoped_lock lock{mutex_};
        initially_stopped = stop_requested_locked();
    }
    if (initially_stopped)
    {
        publish_startup(std::unexpected(cancelled_startup()));
        publish_activation(std::unexpected(cancelled_activation()));
        return requested_stop_result();
    }

    throw_if_abrupt_exit_requested();

    if (config_.worker_count == 0 || config_.cache == nullptr || config_.cache->shard_count() < config_.worker_count ||
        !is_valid_recovery_config(config_.recovery))
    {
        SupervisorStartupError error{
            .code = SupervisorStartupErrorCode::InvalidConfiguration, .create_error = std::nullopt, .runtime_error = std::nullopt};
        publish_startup(std::unexpected(error));
        publish_activation(
            std::unexpected(SupervisorActivationError{.code = SupervisorActivationErrorCode::InternalError, .worker_result = std::nullopt}));
        return startup_failure_result(error);
    }

    auto startup_error = create_workers();
    if (!startup_error)
        startup_error = start_worker_threads();
    if (!startup_error)
        startup_error = await_worker_readiness();

    if (startup_error)
    {
        publish_startup(std::unexpected(*startup_error));
        publish_activation(std::unexpected(startup_error->code == SupervisorStartupErrorCode::Cancelled
                                               ? cancelled_activation()
                                               : SupervisorActivationError{.code          = SupervisorActivationErrorCode::InternalError,
                                                                           .worker_id     = startup_error->worker_id,
                                                                           .instance_id   = startup_error->instance_id,
                                                                           .worker_result = std::nullopt}));
        request_all_worker_stops();
        static_cast<void>(join_and_reset_all());
        if (startup_error->code == SupervisorStartupErrorCode::Cancelled)
            return requested_stop_result();
        return startup_failure_result(*startup_error);
    }

    const uint16_t bound_port = records_.front()->current_instance_->bound_port();
    publish_startup(SupervisorStartupInfo{bound_port, records_.size()});

    auto activation_error = await_activation_command_and_workers();
    if (activation_error)
    {
        publish_activation(std::unexpected(*activation_error));

        bool stopping = false;
        {
            std::scoped_lock lock{mutex_};
            stopping = stop_requested_locked();
        }

        if (stopping || activation_error->code == SupervisorActivationErrorCode::Cancelled)
        {
            request_all_worker_stops();
            static_cast<void>(join_and_reset_all());
            return requested_stop_result();
        }

        WorkerRunResult normalized = activation_error->worker_result.value_or(
            WorkerRunResult{WorkerRunOutcome::FatalExit, WorkerRuntimeError{WorkerRuntimeStep::AwaitActivation, 0}});
        SupervisorRunErrorCode error_code = SupervisorRunErrorCode::WorkerFatalExit;
        if (normalized.outcome == WorkerRunOutcome::RequestedStop)
        {
            normalized.outcome = WorkerRunOutcome::FatalExit;
            error_code         = SupervisorRunErrorCode::UnexpectedWorkerStop;
        }

        request_all_worker_stops();
        static_cast<void>(join_and_reset_all());
        return SupervisorRunResult{
            .outcome       = SupervisorRunOutcome::FatalExit,
            .error_code    = error_code,
            .worker_id     = activation_error->worker_id,
            .instance_id   = activation_error->instance_id,
            .startup_error = std::nullopt,
            .worker_result = normalized,
        };
    }

    publish_activation(SupervisorActivationResult{});
    SupervisorRunResult result = monitor_active_workers();
    request_all_worker_stops();
    // A failed join is not a quiescence proof. Leave owners and tokens intact
    // for the external successor after C itself has been joined.
    if (result.error_code == SupervisorRunErrorCode::WorkerJoinFailed)
        return result;
    if (!join_and_reset_all() && result.outcome != SupervisorRunOutcome::FatalExit)
    {
        result = SupervisorRunResult{
            .outcome       = SupervisorRunOutcome::FatalExit,
            .error_code    = SupervisorRunErrorCode::InternalError,
            .startup_error = std::nullopt,
            .worker_result = std::nullopt,
        };
    }
    return result;
}

std::optional<SupervisorStartupError> WorkerSupervisor::create_workers()
{
    uint16_t port = config_.requested_port;
    for (auto &record : records_)
    {
        if (auto error = create_worker(*record, port))
            return error;
        if (record->worker_id_ == 0 && config_.requested_port == 0)
            port = record->current_instance_->bound_port();
    }
    return std::nullopt;
}

std::optional<SupervisorStartupError> WorkerSupervisor::create_worker(WorkerRecord &record, uint16_t port)
{
    const auto failure = [&record](SupervisorStartupErrorCode code, int error_number = 0, std::optional<WorkerInitError> create_error = std::nullopt)
    {
        return SupervisorStartupError{.code          = code,
                                      .worker_id     = record.worker_id_,
                                      .instance_id   = record.instance_id_,
                                      .error_number  = error_number,
                                      .create_error  = create_error,
                                      .runtime_error = std::nullopt};
    };
    WorkerSupervisorFaultHooks hooks;
    try
    {
        {
            std::scoped_lock lock{mutex_};
            if (abrupt_exit_requested_)
                throw InjectedSupervisorFailure{};
            if (stop_requested_locked())
                return cancelled_startup();
            if (record.recovery_episode_)
            {
                ++record.recovery_attempts_;
                ++health_.restart_count;
            }
            if (record.instance_id_ == std::numeric_limits<uint64_t>::max())
                return failure(SupervisorStartupErrorCode::InstanceIdExhausted);
            // The previous thread and all its callbacks must be gone before
            // replacing either the stop source or the exact-instance slots.
            if (record.current_instance_ || record.current_thread_.joinable())
                return failure(SupervisorStartupErrorCode::InternalError);
            ++record.instance_id_;
            record.state_                = WorkerRecordState::Creating;
            record.instance_stop_source_ = std::stop_source{};
            record.ready_                = {};
            record.activated_            = {};
            record.completion_           = {};
            record.activation_allowed_   = false;
            record.data_plane_allowed_   = false;
            hooks                        = config_.fault_hooks;
        }

        std::optional<FilterWorkerRegistration> registration;
        if (config_.filter_publication != nullptr)
        {
            registration = config_.filter_publication->register_worker(record.worker_id_, record.instance_id_, record.epoch_);
            if (!registration)
                return failure(SupervisorStartupErrorCode::InternalError);
        }
        else
        {
            record.epoch_.observed_generation.store(kUnobservedFilterGeneration, std::memory_order_relaxed);
            record.epoch_.registration_state.store(WorkerRegistrationState::Starting, std::memory_order_relaxed);
            record.epoch_.published_instance_id.store(record.instance_id_, std::memory_order_release);
        }

        if (record.instance_id_ >= hooks.failure_from_instance && hooks.create_failure_worker == record.worker_id_)
        {
            const WorkerInitError injected{hooks.create_failure_step, configured_error_or(hooks.create_failure_error, EIO)};
            return failure(SupervisorStartupErrorCode::WorkerCreateFailed, injected.error_number, injected);
        }

        WorkerLoop::CreateResult created =
            config_.filter_publication != nullptr
                ? WorkerLoop::create(record.worker_id_, port, config_.cache->shard(record.worker_id_), *config_.filter_publication,
                                     std::move(registration->snapshot), record.epoch_, record.instance_id_, config_.upstream)
                : WorkerLoop::create(record.worker_id_, port, config_.cache->shard(record.worker_id_), config_.upstream);
        if (!created)
            return failure(SupervisorStartupErrorCode::WorkerCreateFailed, created.error().error_number, created.error());

        {
            std::scoped_lock lock{mutex_};
            record.current_instance_ = std::move(*created);
            record.state_            = WorkerRecordState::Starting;
        }
        return std::nullopt;
    }
    catch (const std::bad_alloc &)
    {
        return failure(SupervisorStartupErrorCode::WorkerCreateFailed, ENOMEM);
    }
    catch (const std::system_error &error)
    {
        return failure(SupervisorStartupErrorCode::WorkerCreateFailed, error.code().value());
    }
    // Failed registrations are quiesced by join_and_reset(), after all local
    // owners above have unwound. This same path serves startup and replacement.
}

std::optional<SupervisorStartupError> WorkerSupervisor::start_worker_threads()
{
    for (auto &record : records_)
    {
        if (auto error = start_worker_thread(*record))
            return error;
    }
    return std::nullopt;
}

std::optional<SupervisorStartupError> WorkerSupervisor::start_worker_thread(WorkerRecord &record)
{
    WorkerSupervisorFaultHooks hooks;
    {
        std::scoped_lock lock{mutex_};
        if (abrupt_exit_requested_)
            throw InjectedSupervisorFailure{};
        if (stop_requested_locked())
            return cancelled_startup();
        hooks = config_.fault_hooks;
    }
    record.observer_->bind(record.instance_id_);
    const auto failure = [&record](int error_number)
    {
        return SupervisorStartupError{.code          = SupervisorStartupErrorCode::WorkerThreadStartFailed,
                                      .worker_id     = record.worker_id_,
                                      .instance_id   = record.instance_id_,
                                      .error_number  = error_number,
                                      .create_error  = std::nullopt,
                                      .runtime_error = std::nullopt};
    };
    if (record.instance_id_ >= hooks.failure_from_instance && hooks.thread_failure_worker == record.worker_id_)
        return failure(configured_error_or(hooks.thread_failure_error, EAGAIN));
    try
    {
        const uint64_t instance_id = record.instance_id_;
        record.current_thread_     = std::jthread([this, &record, instance_id](std::stop_token token) { worker_entry(record, instance_id, token); });
    }
    catch (const std::system_error &error)
    {
        return failure(error.code().value());
    }
    catch (const std::bad_alloc &)
    {
        return failure(ENOMEM);
    }
    return std::nullopt;
}

std::optional<SupervisorStartupError> WorkerSupervisor::await_worker_readiness()
{
    std::unique_lock lock{mutex_};
    while (true)
    {
        if (abrupt_exit_requested_)
            throw InjectedSupervisorFailure{};
        if (stop_requested_locked())
            return cancelled_startup();

        for (auto &owned_record : records_)
        {
            WorkerRecord &record = *owned_record;
            if (record.state_ == WorkerRecordState::Ready)
                continue;

            if (record.ready_.published && record.ready_.instance_id == record.instance_id_)
            {
                if (record.ready_.result.outcome != WorkerReadyOutcome::Ready)
                {
                    return SupervisorStartupError{
                        .code          = SupervisorStartupErrorCode::WorkerInitFailed,
                        .worker_id     = record.worker_id_,
                        .instance_id   = record.instance_id_,
                        .error_number  = record.ready_.result.error ? record.ready_.result.error->error_number : 0,
                        .create_error  = std::nullopt,
                        .runtime_error = record.ready_.result.error,
                    };
                }
                if (config_.filter_publication != nullptr &&
                    !config_.filter_publication->mark_worker_registered(record.worker_id_, record.instance_id_, record.epoch_))
                {
                    // The publication that raced Ready captured this Starting
                    // token. Wake the gate waiter; it must refresh on its own
                    // thread before C accepts Ready.
                    wakeup_.notify_all();
                    continue;
                }
                record.state_ = WorkerRecordState::Ready;
                if (config_.filter_publication == nullptr)
                    record.epoch_.registration_state.store(WorkerRegistrationState::Registered, std::memory_order_release);
                continue;
            }

            if (record.completion_.published && record.completion_.instance_id == record.instance_id_)
            {
                record.state_       = WorkerRecordState::Exited;
                record.last_result_ = record.completion_.result;
                return SupervisorStartupError{
                    .code          = SupervisorStartupErrorCode::WorkerExitedBeforeReady,
                    .worker_id     = record.worker_id_,
                    .instance_id   = record.instance_id_,
                    .error_number  = record.completion_.result.error ? record.completion_.result.error->error_number : 0,
                    .create_error  = std::nullopt,
                    .runtime_error = record.completion_.result.error,
                };
            }
        }
        bool all_ready = true;
        for (const auto &record : records_)
            all_ready = all_ready && record->state_ == WorkerRecordState::Ready;
        if (all_ready)
            return std::nullopt;

        wakeup_.wait(lock);
    }
}

std::optional<SupervisorActivationError> WorkerSupervisor::await_activation_command_and_workers()
{
    std::unique_lock lock{mutex_};
    while (true)
    {
        if (abrupt_exit_requested_)
            throw InjectedSupervisorFailure{};
        if (stop_requested_locked())
            return cancelled_activation();

        for (auto &owned_record : records_)
        {
            WorkerRecord &record = *owned_record;
            if (record.completion_.published && record.completion_.instance_id == record.instance_id_)
            {
                record.state_       = WorkerRecordState::Exited;
                record.last_result_ = record.completion_.result;
                return SupervisorActivationError{
                    .code          = SupervisorActivationErrorCode::WorkerExitedBeforeActivation,
                    .worker_id     = record.worker_id_,
                    .instance_id   = record.instance_id_,
                    .worker_result = record.completion_.result,
                };
            }
        }

        if (!activation_requested_)
        {
            wakeup_.wait(lock);
            continue;
        }

        for (auto &owned_record : records_)
        {
            WorkerRecord &record = *owned_record;
            if (record.state_ == WorkerRecordState::Running)
                continue;
            if (record.activated_.published && record.activated_.instance_id == record.instance_id_)
                record.state_ = WorkerRecordState::Running;
        }
        bool all_activated = true;
        for (const auto &record : records_)
            all_activated = all_activated && record->state_ == WorkerRecordState::Running;
        if (all_activated)
            return std::nullopt;

        wakeup_.wait(lock);
    }
}

SupervisorRunResult WorkerSupervisor::monitor_active_workers()
{
    std::unique_lock lock{mutex_};
    while (true)
    {
        if (abrupt_exit_requested_)
            throw InjectedSupervisorFailure{};
        if (stop_requested_locked())
            return requested_stop_result();

        if (snapshot_publication_pending_)
        {
            snapshot_publication_pending_ = false;
            for (const auto &record : records_)
            {
                if (record->current_instance_ && !record->current_instance_->request_filter_refresh())
                {
                    return SupervisorRunResult{.outcome       = SupervisorRunOutcome::FatalExit,
                                               .error_code    = SupervisorRunErrorCode::InternalError,
                                               .worker_id     = record->worker_id_,
                                               .instance_id   = record->instance_id_,
                                               .error_number  = errno,
                                               .startup_error = std::nullopt,
                                               .worker_result = std::nullopt};
                }
            }
            wakeup_.notify_all(); // Also wake Starting/Ready generation gates.
        }

        if (unexpected_stop_worker_)
        {
            const size_t   selected    = *unexpected_stop_worker_;
            const uint64_t instance_id = unexpected_stop_instance_;
            unexpected_stop_worker_.reset();
            WorkerRecord &record   = *records_[selected];
            WorkerLoop   *instance = record.instance_id_ == instance_id ? record.current_instance_.get() : nullptr;
            lock.unlock();
            if (instance != nullptr)
                instance->request_stop();
            lock.lock();
            continue;
        }

        bool progressed    = false;
        auto next_deadline = Clock::time_point::max();
        for (auto &owned_record : records_)
        {
            WorkerRecord &record = *owned_record;
            const bool    live   = record.state_ == WorkerRecordState::Starting || record.state_ == WorkerRecordState::Ready ||
                              record.state_ == WorkerRecordState::Running;
            const bool completed   = live && record.completion_.published && record.completion_.instance_id == record.instance_id_;
            const bool init_failed = live && record.ready_.published && record.ready_.instance_id == record.instance_id_ &&
                                     record.ready_.result.outcome != WorkerReadyOutcome::Ready;
            // Completion wins over Ready and stability checks. Use the actual
            // completion time, so a busy C cannot turn a short-lived worker
            // into a stable instance just by observing its exit later.
            if (completed || init_failed)
            {
                WorkerFailure failure;
                failure.worker_id   = record.worker_id_;
                failure.instance_id = record.instance_id_;
                if (init_failed)
                {
                    failure.code          = WorkerFailureCode::InitFailed;
                    failure.runtime_error = record.ready_.result.error;
                }
                else
                {
                    failure.code          = record.completion_.result.outcome == WorkerRunOutcome::RequestedStop ? WorkerFailureCode::UnexpectedStop
                                                                                                                 : WorkerFailureCode::FatalExit;
                    failure.runtime_error = record.completion_.result.error;
                    if (failure.code == WorkerFailureCode::UnexpectedStop)
                        failure.runtime_error = WorkerRuntimeError{WorkerRuntimeStep::UnexpectedStop, 0};
                }
                failure.error_number = failure.runtime_error ? failure.runtime_error->error_number : 0;
                lock.unlock();
                auto terminal = handle_worker_failure(record, failure);
                if (terminal)
                    return *terminal;
                lock.lock();
                progressed = true;
                break;
            }

            if (record.state_ == WorkerRecordState::Starting && record.ready_.published && record.ready_.instance_id == record.instance_id_)
            {
                lock.unlock();
                recovery_test_point(record, WorkerRecoveryTestPoint::Ready);
                lock.lock();
                if (stop_requested_locked())
                    return requested_stop_result();
                if (record.completion_.published)
                {
                    progressed = true;
                    break;
                }
                if (config_.filter_publication &&
                    !config_.filter_publication->mark_worker_registered(record.worker_id_, record.instance_id_, record.epoch_))
                {
                    wakeup_.notify_all();
                    continue;
                }
                if (!config_.filter_publication)
                    record.epoch_.registration_state.store(WorkerRegistrationState::Registered, std::memory_order_release);
                record.state_              = WorkerRecordState::Ready;
                record.activation_allowed_ = true;
                wakeup_.notify_all();
                progressed = true;
            }
            if (record.state_ == WorkerRecordState::Ready && record.activated_.published && record.activated_.instance_id == record.instance_id_)
            {
                lock.unlock();
                recovery_test_point(record, WorkerRecoveryTestPoint::Activated);
                lock.lock();
                if (stop_requested_locked())
                    return requested_stop_result();
                if (record.completion_.published)
                {
                    progressed = true;
                    break;
                }
                record.state_              = WorkerRecordState::Running;
                record.data_plane_allowed_ = true;
                record.stable_at_          = deadline_after(Clock::now(), config_.recovery.stability_window);
                ++health_.restart_success_count;
                wakeup_.notify_all();
                lock.unlock();
                recovery_test_point(record, WorkerRecoveryTestPoint::Running);
                publish_health();
                lock.lock();
                progressed = true;
            }

            // Publishing health releases mutex_; completion may have arrived
            // during that callback. Do not award stability to that exit.
            if (record.state_ == WorkerRecordState::Running && record.completion_.published)
            {
                progressed = true;
                break;
            }
            const auto now = Clock::now();
            if (record.state_ == WorkerRecordState::Running && record.recovery_episode_)
            {
                if (now >= record.stable_at_)
                {
                    record.recovery_episode_  = false;
                    record.recovery_attempts_ = 0;
                    record.next_backoff_      = config_.recovery.initial_backoff;
                }
                else
                    next_deadline = std::min(next_deadline, record.stable_at_);
            }
            if (record.state_ != WorkerRecordState::Backoff)
                continue;
            if (now < record.restart_at_)
            {
                next_deadline = std::min(next_deadline, record.restart_at_);
                continue;
            }

            lock.unlock();
            recovery_test_point(record, WorkerRecoveryTestPoint::BeforeCreate);
            auto error = create_worker(record, effective_bound_port_);
            publish_health();
            if (!error)
            {
                recovery_test_point(record, WorkerRecoveryTestPoint::AfterCreate);
                error = start_worker_thread(record);
            }
            if (error)
            {
                if (error->code == SupervisorStartupErrorCode::Cancelled)
                    return requested_stop_result();
                auto terminal = handle_worker_failure(record, creation_failure(*error));
                if (terminal)
                    return *terminal;
            }
            lock.lock();
            progressed = true;
            break;
        }
        if (progressed)
            continue;
        // State and every notifying producer share mutex_. A replacement's
        // Ready wait does not block C from servicing other workers or updates.
        if (next_deadline == Clock::time_point::max())
            wakeup_.wait(lock);
        else
            wakeup_.wait_until(lock, next_deadline);
    }
}

std::optional<SupervisorRunResult> WorkerSupervisor::handle_worker_failure(WorkerRecord &record, WorkerFailure failure)
{
    {
        std::scoped_lock lock{mutex_};
        if (stop_requested_locked())
            return requested_stop_result();
        if (record.instance_id_ > 1)
            ++health_.restart_failure_count;
        if (record.state_ == WorkerRecordState::Running && record.recovery_episode_ && record.completion_.completed_at >= record.stable_at_)
        {
            record.recovery_episode_  = false;
            record.recovery_attempts_ = 0;
        }
        if (!record.recovery_episode_)
        {
            record.recovery_episode_ = data_plane_released_;
            record.next_backoff_     = config_.recovery.initial_backoff;
        }
        record.state_      = record.completion_.published ? WorkerRecordState::Exited : WorkerRecordState::Stopping;
        health_.last_error = failure;
    }
    publish_health();
    if (!join_and_reset(record))
    {
        failure.code = WorkerFailureCode::JoinFailed;
        return fail_worker_service(failure);
    }

    {
        std::scoped_lock lock{mutex_};
        if (failure.code == WorkerFailureCode::UnexpectedStop || failure.code == WorkerFailureCode::FatalExit ||
            failure.code == WorkerFailureCode::InitFailed)
            record.last_result_ = WorkerRunResult{WorkerRunOutcome::FatalExit, failure.runtime_error};
        if (stop_requested_locked())
            return requested_stop_result();
        if (data_plane_released_ && record.recovery_episode_ && config_.recovery.policy == WorkerFailurePolicy::Restart &&
            failure.code != WorkerFailureCode::InstanceIdExhausted)
        {
            if (record.recovery_attempts_ < config_.recovery.max_attempts)
            {
                record.state_        = WorkerRecordState::Backoff;
                record.restart_at_   = deadline_after(Clock::now(), record.next_backoff_);
                record.next_backoff_ = doubled_backoff(record.next_backoff_, config_.recovery.max_backoff);
                return std::nullopt;
            }
            failure.budget_exhausted = true;
        }
    }
    return fail_worker_service(failure);
}

SupervisorRunResult WorkerSupervisor::fail_worker_service(const WorkerFailure &failure) noexcept
{
    bool report;
    {
        std::scoped_lock lock{mutex_};
        report             = data_plane_released_ && !stop_requested_locked();
        health_.last_error = failure;
    }
    publish_health();
    if (report && config_.fatal_reporter)
        config_.fatal_reporter(config_.fatal_reporter_context, failure);
    return SupervisorRunResult{
        .outcome       = SupervisorRunOutcome::FatalExit,
        .error_code    = failure.code == WorkerFailureCode::JoinFailed       ? SupervisorRunErrorCode::WorkerJoinFailed
                         : failure.code == WorkerFailureCode::UnexpectedStop ? SupervisorRunErrorCode::UnexpectedWorkerStop
                                                                             : SupervisorRunErrorCode::WorkerFatalExit,
        .worker_id     = failure.worker_id,
        .instance_id   = failure.instance_id,
        .error_number  = failure.error_number,
        .startup_error = std::nullopt,
        .worker_result = WorkerRunResult{WorkerRunOutcome::FatalExit, failure.runtime_error},
    };
}

void WorkerSupervisor::publish_health() noexcept
{
    SupervisorHealthSnapshot snapshot;
    {
        std::scoped_lock lock{mutex_};
        health_.available_workers = 0;
        for (const auto &record : records_)
            health_.available_workers += record->state_ == WorkerRecordState::Running && record->data_plane_allowed_ &&
                                         !(record->completion_.published && record->completion_.instance_id == record->instance_id_);
        snapshot = health_;
    }
    // Never take the DNS lifecycle lock while holding mutex_: start/stop
    // already use the opposite direction to close admission atomically.
    if (config_.health_reporter)
        config_.health_reporter(config_.fatal_reporter_context, snapshot);
}

void WorkerSupervisor::recovery_test_point(WorkerRecord &record, WorkerRecoveryTestPoint point) noexcept
{
    WorkerSupervisorFaultHooks hooks;
    {
        std::scoped_lock lock{mutex_};
        hooks = config_.fault_hooks;
    }
    if (hooks.recovery_probe)
        hooks.recovery_probe(hooks.recovery_probe_context, record.worker_id_, record.instance_id_, point);
}

void WorkerSupervisor::worker_entry(WorkerRecord &record, uint64_t instance_id, std::stop_token thread_stop_token) noexcept
{
    std::stop_callback forward_stop{thread_stop_token, [&record] { record.instance_stop_source_.request_stop(); }};
    WorkerRunResult    result{WorkerRunOutcome::FatalExit, WorkerRuntimeError{WorkerRuntimeStep::UnhandledException, 0}};
    try
    {
        result = record.current_instance_->run(record.instance_stop_source_.get_token(), record.observer_.get());
    }
    catch (...)
    {
    }
    report_worker_completion(record, instance_id, std::move(result));
}

void WorkerSupervisor::report_worker_ready(WorkerRecord &record, uint64_t instance_id, WorkerReadyResult result) noexcept
{
    bool inject_failure = false;
    {
        std::scoped_lock lock{mutex_};
        if (instance_id != record.instance_id_ || record.ready_.published)
            return;

        if (result.outcome == WorkerReadyOutcome::Ready && record.instance_id_ >= config_.fault_hooks.failure_from_instance &&
            config_.fault_hooks.runtime_init_failure_worker == record.worker_id_)
        {
            result = WorkerReadyResult{
                WorkerReadyOutcome::InitError,
                WorkerRuntimeError{config_.fault_hooks.runtime_init_failure_step,
                                   configured_error_or(config_.fault_hooks.runtime_init_failure_error, EIO)},
            };
            inject_failure = true;
        }

        record.ready_.published   = true;
        record.ready_.instance_id = instance_id;
        record.ready_.result      = std::move(result);
    }
    wakeup_.notify_all();
    if (inject_failure)
        record.instance_stop_source_.request_stop();
}

WorkerRunObserver::GateAction WorkerSupervisor::await_worker_activation(WorkerRecord &record, uint64_t instance_id,
                                                                        std::stop_token stop_token) noexcept
{
    try
    {
        std::unique_lock lock{mutex_};
        const bool       ready = wakeup_.wait(lock, stop_token,
                                              [this, &record, instance_id]
                                              {
                                            return instance_id != record.instance_id_ || record.activation_allowed_ || stop_requested_locked() ||
                                                   record.instance_stop_source_.stop_requested() ||
                                                   (config_.filter_publication != nullptr &&
                                                    config_.filter_publication->worker_needs_refresh(instance_id, record.epoch_));
                                        });
        if (!ready || instance_id != record.instance_id_ || stop_requested_locked() || record.instance_stop_source_.stop_requested())
            return WorkerRunObserver::GateAction::Stop;
        if (config_.filter_publication != nullptr && config_.filter_publication->worker_needs_refresh(instance_id, record.epoch_))
            return WorkerRunObserver::GateAction::RefreshFilter;
        return record.activation_allowed_ ? WorkerRunObserver::GateAction::Proceed : WorkerRunObserver::GateAction::Stop;
    }
    catch (...)
    {
        return WorkerRunObserver::GateAction::Stop;
    }
}

void WorkerSupervisor::report_worker_activated(WorkerRecord &record, uint64_t instance_id) noexcept
{
    {
        std::scoped_lock lock{mutex_};
        if (instance_id != record.instance_id_ || record.activated_.published)
            return;
        record.activated_.published   = true;
        record.activated_.instance_id = instance_id;
    }
    wakeup_.notify_all();
}

WorkerRunObserver::GateAction WorkerSupervisor::await_worker_data_plane(WorkerRecord &record, uint64_t instance_id,
                                                                        std::stop_token stop_token) noexcept
{
    try
    {
        std::unique_lock lock{mutex_};
        const bool       released = wakeup_.wait(lock, stop_token,
                                                 [this, &record, instance_id]
                                                 {
                                               return instance_id != record.instance_id_ || record.data_plane_allowed_ || stop_requested_locked() ||
                                                      abrupt_exit_requested_ || record.instance_stop_source_.stop_requested() ||
                                                      (config_.filter_publication != nullptr &&
                                                       config_.filter_publication->worker_needs_refresh(instance_id, record.epoch_));
                                           });
        if (!released || instance_id != record.instance_id_ || stop_requested_locked() || abrupt_exit_requested_ ||
            record.instance_stop_source_.stop_requested())
            return WorkerRunObserver::GateAction::Stop;
        if (config_.filter_publication != nullptr && config_.filter_publication->worker_needs_refresh(instance_id, record.epoch_))
            return WorkerRunObserver::GateAction::RefreshFilter;
        return record.data_plane_allowed_ ? WorkerRunObserver::GateAction::Proceed : WorkerRunObserver::GateAction::Stop;
    }
    catch (...)
    {
        return WorkerRunObserver::GateAction::Stop;
    }
}

void WorkerSupervisor::report_worker_filter_progress(WorkerRecord &record, uint64_t instance_id) noexcept
{
    {
        std::scoped_lock lock{mutex_};
        if (instance_id != record.instance_id_)
            return;
    }
    wakeup_.notify_all();
}

void WorkerSupervisor::report_worker_completion(WorkerRecord &record, uint64_t instance_id, WorkerRunResult result) noexcept
{
    {
        std::scoped_lock lock{mutex_};
        if (instance_id != record.instance_id_ || record.completion_.published)
            return;
        record.completion_.published    = true;
        record.completion_.instance_id  = instance_id;
        record.completion_.result       = std::move(result);
        record.completion_.completed_at = Clock::now();
    }
    wakeup_.notify_all();
}

SupervisorStartupResult WorkerSupervisor::wait_for_startup(std::stop_token stop_token) noexcept
{
    try
    {
        std::unique_lock lock{mutex_};
        if (!wakeup_.wait(lock, stop_token, [this] { return startup_result_.has_value(); }))
            return std::unexpected(cancelled_startup());
        return *startup_result_;
    }
    catch (...)
    {
        return std::unexpected(
            SupervisorStartupError{.code = SupervisorStartupErrorCode::InternalError, .create_error = std::nullopt, .runtime_error = std::nullopt});
    }
}

bool WorkerSupervisor::request_activation() noexcept
{
    {
        std::scoped_lock lock{mutex_};
        if (stop_requested_locked() || activation_requested_ || activation_result_ || !run_active_.load(std::memory_order_acquire) ||
            !startup_result_ || !startup_result_->has_value())
            return false;
        activation_requested_ = true;
        for (auto &record : records_)
            record->activation_allowed_ = true;
    }
    wakeup_.notify_all();
    return true;
}

SupervisorActivationResult WorkerSupervisor::wait_for_activation(std::stop_token stop_token) noexcept
{
    try
    {
        std::unique_lock lock{mutex_};
        if (!wakeup_.wait(lock, stop_token, [this] { return activation_result_.has_value(); }))
            return std::unexpected(cancelled_activation());
        return *activation_result_;
    }
    catch (...)
    {
        return std::unexpected(SupervisorActivationError{.code = SupervisorActivationErrorCode::InternalError, .worker_result = std::nullopt});
    }
}

SupervisorActivationResult WorkerSupervisor::release_data_plane() noexcept
{
    {
        std::scoped_lock lock{mutex_};
        if (stop_requested_locked())
            return std::unexpected(cancelled_activation());
        if (abrupt_exit_requested_)
            return std::unexpected(SupervisorActivationError{.code = SupervisorActivationErrorCode::InternalError, .worker_result = std::nullopt});

        for (const auto &record : records_)
        {
            const bool exact_completion = record->completion_.published && record->completion_.instance_id == record->instance_id_;
            if (record->state_ != WorkerRecordState::Running || exact_completion)
            {
                return std::unexpected(SupervisorActivationError{
                    .code          = SupervisorActivationErrorCode::WorkerExitedBeforeActivation,
                    .worker_id     = record->worker_id_,
                    .instance_id   = record->instance_id_,
                    .worker_result = exact_completion ? std::optional{record->completion_.result} : record->last_result_,
                });
            }
        }
        if (data_plane_released_ || !run_active_.load(std::memory_order_acquire) || !activation_result_ || !activation_result_->has_value())
            return std::unexpected(SupervisorActivationError{.code = SupervisorActivationErrorCode::InternalError, .worker_result = std::nullopt});
        data_plane_released_  = true;
        effective_bound_port_ = startup_result_ ? startup_result_->value().bound_port : config_.requested_port;
        for (auto &record : records_)
            record->data_plane_allowed_ = true;
    }
    wakeup_.notify_all();
    return {};
}

void WorkerSupervisor::request_stop() noexcept
{
    {
        std::scoped_lock lock{mutex_};
        stop_requested_ = true;
    }
    wakeup_.notify_all();
    request_all_worker_stops();
}

void WorkerSupervisor::snapshot_published(FilterGeneration generation) noexcept
{
    {
        std::scoped_lock lock{mutex_};
        if (generation <= published_generation_)
            return;
        published_generation_         = generation;
        snapshot_publication_pending_ = true;
        if (abrupt_exit_after_publication_requested_)
        {
            abrupt_exit_after_publication_requested_ = false;
            abrupt_exit_requested_                   = true;
        }
    }
    wakeup_.notify_all();
}

void WorkerSupervisor::request_all_worker_stops() noexcept
{
    for (const auto &record : records_)
    {
        // request_stop() invokes callbacks synchronously; copy under mutex,
        // invoke outside it. Replacement swaps the source under this mutex
        // and checks global admission, so stop cannot miss a new instance.
        const auto source = [this, &record]
        {
            std::scoped_lock lock{mutex_};
            return record->instance_stop_source_;
        }();
        source.request_stop();
    }
    wakeup_.notify_all();
}

void WorkerSupervisor::publish_startup(SupervisorStartupResult result) noexcept
{
    try
    {
        {
            std::scoped_lock lock{mutex_};
            if (startup_result_)
                return;
            startup_result_.emplace(std::move(result));
        }
        wakeup_.notify_all();
    }
    catch (...)
    {
    }
}

void WorkerSupervisor::publish_activation(SupervisorActivationResult result) noexcept
{
    try
    {
        {
            std::scoped_lock lock{mutex_};
            if (activation_result_)
                return;
            activation_result_.emplace(std::move(result));
        }
        wakeup_.notify_all();
    }
    catch (...)
    {
    }
}

void WorkerSupervisor::publish_abrupt_failure() noexcept
{
    publish_startup(std::unexpected(
        SupervisorStartupError{.code = SupervisorStartupErrorCode::InternalError, .create_error = std::nullopt, .runtime_error = std::nullopt}));
    publish_activation(
        std::unexpected(SupervisorActivationError{.code = SupervisorActivationErrorCode::InternalError, .worker_result = std::nullopt}));
}

void WorkerSupervisor::finish_run() noexcept
{
    {
        std::scoped_lock lock{mutex_};
        run_active_.store(false, std::memory_order_release);
    }
    wakeup_.notify_all();
}

bool WorkerSupervisor::join_and_reset_all() noexcept
{
    bool success = true;
    for (auto &record : records_)
        success = join_and_reset(*record) && success;
    return success;
}

bool WorkerSupervisor::join_and_reset(WorkerRecord &record) noexcept
{
    record.instance_stop_source_.request_stop();
    {
        std::scoped_lock lock{mutex_};
        if (join_failure_worker_once_ == record.worker_id_)
        {
            join_failure_worker_once_ = kInvalidWorkerId;
            return false;
        }
        if (record.current_thread_.joinable() && record.state_ != WorkerRecordState::Exited)
            record.state_ = WorkerRecordState::Stopping;
    }

    if (record.current_thread_.joinable())
    {
        try
        {
            if (record.current_thread_.get_id() == std::this_thread::get_id())
                return false;
            record.current_thread_.join();
        }
        catch (...)
        {
            return false;
        }
    }

    {
        std::scoped_lock lock{mutex_};
        if (record.completion_.published && record.completion_.instance_id == record.instance_id_)
            record.last_result_ = record.completion_.result;
        record.state_ = WorkerRecordState::Joined;
        if (record.current_instance_)
            record.last_stats_ = record.current_instance_->stats();
    }

    record.current_thread_ = std::jthread{};
    record.current_instance_.reset();
    if (config_.filter_publication != nullptr)
        config_.filter_publication->quiesce_worker(record.worker_id_, record.instance_id_, record.epoch_);
    else
    {
        record.epoch_.quiesced_through_instance_id.store(record.instance_id_, std::memory_order_release);
        record.epoch_.registration_state.store(WorkerRegistrationState::Unregistered, std::memory_order_release);
    }
    {
        std::scoped_lock lock{mutex_};
        record.state_              = WorkerRecordState::Offline;
        record.activation_allowed_ = false;
        record.data_plane_allowed_ = false;
    }
    wakeup_.notify_all();
    return true;
}

bool WorkerSupervisor::emergency_join_all() noexcept
{
    if (run_active_.load(std::memory_order_acquire))
        return false;
    request_stop();
    {
        std::scoped_lock lock{mutex_};
        if (emergency_join_failure_once_)
        {
            emergency_join_failure_once_ = false;
            return false;
        }
    }
    return join_and_reset_all();
}

void WorkerSupervisor::inject_abrupt_exit_for_testing() noexcept
{
    {
        std::scoped_lock lock{mutex_};
        abrupt_exit_requested_ = true;
    }
    wakeup_.notify_all();
}

void WorkerSupervisor::inject_abrupt_exit_after_next_publication_for_testing() noexcept
{
    {
        std::scoped_lock lock{mutex_};
        abrupt_exit_after_publication_requested_ = true;
    }
    wakeup_.notify_all();
}

bool WorkerSupervisor::inject_worker_unexpected_stop_for_testing(size_t worker_id) noexcept
{
    {
        std::scoped_lock lock{mutex_};
        if (!run_active_.load(std::memory_order_acquire) || worker_id >= records_.size() || unexpected_stop_worker_ || !data_plane_released_)
            return false;
        if (records_[worker_id]->state_ != WorkerRecordState::Running || records_[worker_id]->completion_.published)
            return false;
        unexpected_stop_worker_   = worker_id;
        unexpected_stop_instance_ = records_[worker_id]->instance_id_;
    }
    wakeup_.notify_all();
    return true;
}

bool WorkerSupervisor::inject_worker_precommit_failure_for_testing(size_t worker_id) noexcept
{
    {
        std::scoped_lock lock{mutex_};
        if (!run_active_.load(std::memory_order_acquire) || worker_id >= records_.size() || data_plane_released_ || !activation_result_ ||
            !activation_result_->has_value())
            return false;

        WorkerRecord &record = *records_[worker_id];
        if (record.state_ != WorkerRecordState::Running || record.completion_.published)
            return false;

        record.completion_.published   = true;
        record.completion_.instance_id = record.instance_id_;
        record.completion_.result      = WorkerRunResult{WorkerRunOutcome::FatalExit, WorkerRuntimeError{WorkerRuntimeStep::AwaitActivation, EIO}};
    }
    wakeup_.notify_all();
    return true;
}

void WorkerSupervisor::inject_emergency_join_failure_once_for_testing() noexcept
{
    std::scoped_lock lock{mutex_};
    emergency_join_failure_once_ = true;
}

const WorkerEpoch &WorkerSupervisor::epoch(size_t worker_id) const
{
    return records_.at(worker_id)->epoch_;
}

void WorkerSupervisor::throw_if_abrupt_exit_requested()
{
    std::scoped_lock lock{mutex_};
    if (abrupt_exit_requested_)
        throw InjectedSupervisorFailure{};
}

} // namespace dns::server
