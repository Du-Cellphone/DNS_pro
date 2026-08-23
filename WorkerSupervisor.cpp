#include "WorkerSupervisor.h"

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

    if (config_.worker_count == 0 || config_.cache == nullptr || config_.cache->shard_count() < config_.worker_count)
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
    for (auto &owned_record : records_)
    {
        WorkerRecord &record = *owned_record;
        {
            std::scoped_lock lock{mutex_};
            if (abrupt_exit_requested_)
                throw InjectedSupervisorFailure{};
            if (stop_requested_locked())
                return cancelled_startup();
        }

        if (record.instance_id_ == std::numeric_limits<uint64_t>::max())
        {
            return SupervisorStartupError{
                .code          = SupervisorStartupErrorCode::InstanceIdExhausted,
                .worker_id     = record.worker_id_,
                .create_error  = std::nullopt,
                .runtime_error = std::nullopt,
            };
        }

        ++record.instance_id_;
        record.state_ = WorkerRecordState::Creating;
        std::optional<FilterWorkerRegistration> registration;
        if (config_.filter_publication != nullptr)
        {
            registration = config_.filter_publication->register_worker(record.worker_id_, record.instance_id_, record.epoch_);
            if (!registration)
            {
                return SupervisorStartupError{
                    .code          = SupervisorStartupErrorCode::InternalError,
                    .worker_id     = record.worker_id_,
                    .instance_id   = record.instance_id_,
                    .create_error  = std::nullopt,
                    .runtime_error = std::nullopt,
                };
            }
        }
        else
        {
            record.epoch_.observed_generation.store(kUnobservedFilterGeneration, std::memory_order_relaxed);
            record.epoch_.registration_state.store(WorkerRegistrationState::Starting, std::memory_order_relaxed);
            record.epoch_.published_instance_id.store(record.instance_id_, std::memory_order_release);
        }

        if (config_.fault_hooks.create_failure_worker == record.worker_id_)
        {
            const WorkerInitError injected{config_.fault_hooks.create_failure_step,
                                           configured_error_or(config_.fault_hooks.create_failure_error, EIO)};
            registration.reset();
            if (config_.filter_publication != nullptr)
                config_.filter_publication->quiesce_worker(record.worker_id_, record.instance_id_, record.epoch_);
            return SupervisorStartupError{
                .code          = SupervisorStartupErrorCode::WorkerCreateFailed,
                .worker_id     = record.worker_id_,
                .instance_id   = record.instance_id_,
                .error_number  = injected.error_number,
                .create_error  = injected,
                .runtime_error = std::nullopt,
            };
        }

        WorkerLoop::CreateResult created =
            config_.filter_publication != nullptr
                ? WorkerLoop::create(record.worker_id_, port, config_.cache->shard(record.worker_id_), *config_.filter_publication,
                                     std::move(registration->snapshot), record.epoch_, record.instance_id_, config_.upstream)
                : WorkerLoop::create(record.worker_id_, port, config_.cache->shard(record.worker_id_), config_.upstream);
        if (!created)
        {
            registration.reset();
            if (config_.filter_publication != nullptr)
                config_.filter_publication->quiesce_worker(record.worker_id_, record.instance_id_, record.epoch_);
            return SupervisorStartupError{
                .code          = SupervisorStartupErrorCode::WorkerCreateFailed,
                .worker_id     = record.worker_id_,
                .instance_id   = record.instance_id_,
                .error_number  = created.error().error_number,
                .create_error  = created.error(),
                .runtime_error = std::nullopt,
            };
        }

        record.current_instance_ = std::move(*created);
        record.state_            = WorkerRecordState::Starting;
        if (record.worker_id_ == 0 && config_.requested_port == 0)
            port = record.current_instance_->bound_port();
    }
    return std::nullopt;
}

std::optional<SupervisorStartupError> WorkerSupervisor::start_worker_threads()
{
    for (auto &owned_record : records_)
    {
        WorkerRecord &record = *owned_record;
        {
            std::scoped_lock lock{mutex_};
            if (abrupt_exit_requested_)
                throw InjectedSupervisorFailure{};
            if (stop_requested_locked())
                return cancelled_startup();
            record.ready_      = {};
            record.activated_  = {};
            record.completion_ = {};
            record.last_result_.reset();
        }

        record.observer_->bind(record.instance_id_);
        if (config_.fault_hooks.thread_failure_worker == record.worker_id_)
        {
            return SupervisorStartupError{
                .code          = SupervisorStartupErrorCode::WorkerThreadStartFailed,
                .worker_id     = record.worker_id_,
                .instance_id   = record.instance_id_,
                .error_number  = configured_error_or(config_.fault_hooks.thread_failure_error, EAGAIN),
                .create_error  = std::nullopt,
                .runtime_error = std::nullopt,
            };
        }

        try
        {
            const uint64_t instance_id = record.instance_id_;
            record.current_thread_ = std::jthread([this, &record, instance_id](std::stop_token token) { worker_entry(record, instance_id, token); });
        }
        catch (const std::system_error &error)
        {
            return SupervisorStartupError{
                .code          = SupervisorStartupErrorCode::WorkerThreadStartFailed,
                .worker_id     = record.worker_id_,
                .instance_id   = record.instance_id_,
                .error_number  = error.code().value(),
                .create_error  = std::nullopt,
                .runtime_error = std::nullopt,
            };
        }
        catch (const std::bad_alloc &)
        {
            return SupervisorStartupError{
                .code          = SupervisorStartupErrorCode::WorkerThreadStartFailed,
                .worker_id     = record.worker_id_,
                .instance_id   = record.instance_id_,
                .error_number  = ENOMEM,
                .create_error  = std::nullopt,
                .runtime_error = std::nullopt,
            };
        }
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
    while (true)
    {
        WorkerRunResult result;
        size_t          worker_id               = kInvalidWorkerId;
        uint64_t        instance_id             = 0;
        bool            stop_was_requested      = false;
        bool            data_plane_was_released = false;
        {
            std::unique_lock lock{mutex_};
            wakeup_.wait(lock,
                         [this]
                         {
                             return stop_requested_locked() || abrupt_exit_requested_ || unexpected_stop_worker_.has_value() ||
                                    snapshot_publication_pending_ || has_unconsumed_completion_locked();
                         });
            if (abrupt_exit_requested_)
                throw InjectedSupervisorFailure{};
            if (stop_requested_locked())
                return requested_stop_result();

            if (snapshot_publication_pending_)
            {
                snapshot_publication_pending_ = false;
                for (const auto &owned_record : records_)
                {
                    if (owned_record->current_instance_ != nullptr && !owned_record->current_instance_->request_filter_refresh())
                    {
                        return SupervisorRunResult{
                            .outcome       = SupervisorRunOutcome::FatalExit,
                            .error_code    = SupervisorRunErrorCode::InternalError,
                            .worker_id     = owned_record->worker_id_,
                            .instance_id   = owned_record->instance_id_,
                            .error_number  = errno,
                            .startup_error = std::nullopt,
                            .worker_result = std::nullopt,
                        };
                    }
                }
                continue;
            }

            if (unexpected_stop_worker_)
            {
                const size_t selected = *unexpected_stop_worker_;
                unexpected_stop_worker_.reset();
                WorkerLoop *instance = selected < records_.size() ? records_[selected]->current_instance_.get() : nullptr;
                lock.unlock();
                if (instance != nullptr)
                    instance->request_stop();
                continue;
            }

            WorkerRecord *record = first_unconsumed_completion_locked();
            if (record == nullptr)
                continue;
            result                  = record->completion_.result;
            worker_id               = record->worker_id_;
            instance_id             = record->instance_id_;
            stop_was_requested      = record->completion_.stop_was_requested;
            data_plane_was_released = data_plane_released_;
            record->state_          = WorkerRecordState::Exited;
            record->last_result_    = result;
        }

        if (result.outcome == WorkerRunOutcome::RequestedStop && !stop_was_requested)
        {
            const WorkerRunResult reported = result;
            result.outcome                 = WorkerRunOutcome::FatalExit;
            if (data_plane_was_released && config_.fatal_reporter != nullptr)
                config_.fatal_reporter(config_.fatal_reporter_context, worker_id, instance_id, reported);
            return SupervisorRunResult{
                .outcome       = SupervisorRunOutcome::FatalExit,
                .error_code    = SupervisorRunErrorCode::UnexpectedWorkerStop,
                .worker_id     = worker_id,
                .instance_id   = instance_id,
                .startup_error = std::nullopt,
                .worker_result = result,
            };
        }

        if (result.outcome == WorkerRunOutcome::FatalExit)
        {
            if (data_plane_was_released && config_.fatal_reporter != nullptr)
                config_.fatal_reporter(config_.fatal_reporter_context, worker_id, instance_id, result);
            return SupervisorRunResult{
                .outcome       = SupervisorRunOutcome::FatalExit,
                .error_code    = SupervisorRunErrorCode::WorkerFatalExit,
                .worker_id     = worker_id,
                .instance_id   = instance_id,
                .error_number  = result.error ? result.error->error_number : 0,
                .startup_error = std::nullopt,
                .worker_result = result,
            };
        }

        return requested_stop_result();
    }
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

        if (result.outcome == WorkerReadyOutcome::Ready && config_.fault_hooks.runtime_init_failure_worker == record.worker_id_)
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
                                            return instance_id != record.instance_id_ || activation_requested_ || stop_requested_locked() ||
                                                   record.instance_stop_source_.stop_requested() ||
                                                   (config_.filter_publication != nullptr &&
                                                    config_.filter_publication->worker_needs_refresh(instance_id, record.epoch_));
                                        });
        if (!ready || instance_id != record.instance_id_ || stop_requested_locked() || record.instance_stop_source_.stop_requested())
            return WorkerRunObserver::GateAction::Stop;
        if (config_.filter_publication != nullptr && config_.filter_publication->worker_needs_refresh(instance_id, record.epoch_))
            return WorkerRunObserver::GateAction::RefreshFilter;
        return activation_requested_ ? WorkerRunObserver::GateAction::Proceed : WorkerRunObserver::GateAction::Stop;
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
                                               return instance_id != record.instance_id_ || data_plane_released_ || stop_requested_locked() ||
                                                      abrupt_exit_requested_ || record.instance_stop_source_.stop_requested() ||
                                                      (config_.filter_publication != nullptr &&
                                                       config_.filter_publication->worker_needs_refresh(instance_id, record.epoch_));
                                           });
        if (!released || instance_id != record.instance_id_ || stop_requested_locked() || abrupt_exit_requested_ ||
            record.instance_stop_source_.stop_requested())
            return WorkerRunObserver::GateAction::Stop;
        if (config_.filter_publication != nullptr && config_.filter_publication->worker_needs_refresh(instance_id, record.epoch_))
            return WorkerRunObserver::GateAction::RefreshFilter;
        return data_plane_released_ ? WorkerRunObserver::GateAction::Proceed : WorkerRunObserver::GateAction::Stop;
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
        record.completion_.published          = true;
        record.completion_.stop_was_requested = stop_requested_locked() || record.instance_stop_source_.stop_requested();
        record.completion_.instance_id        = instance_id;
        record.completion_.result             = std::move(result);
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
        data_plane_released_ = true;
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
        record->instance_stop_source_.request_stop();
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
    run_active_.store(false, std::memory_order_release);
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
        record.state_ = WorkerRecordState::Offline;
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
        unexpected_stop_worker_ = worker_id;
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

        record.completion_.published          = true;
        record.completion_.stop_was_requested = false;
        record.completion_.instance_id        = record.instance_id_;
        record.completion_.result = WorkerRunResult{WorkerRunOutcome::FatalExit, WorkerRuntimeError{WorkerRuntimeStep::AwaitActivation, EIO}};
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

bool WorkerSupervisor::has_unconsumed_completion_locked() const noexcept
{
    for (const auto &record : records_)
    {
        if ((record->state_ == WorkerRecordState::Running || record->state_ == WorkerRecordState::Ready) && record->completion_.published &&
            record->completion_.instance_id == record->instance_id_)
            return true;
    }
    return false;
}

WorkerRecord *WorkerSupervisor::first_unconsumed_completion_locked() noexcept
{
    for (auto &record : records_)
    {
        if ((record->state_ == WorkerRecordState::Running || record->state_ == WorkerRecordState::Ready) && record->completion_.published &&
            record->completion_.instance_id == record->instance_id_)
            return record.get();
    }
    return nullptr;
}

void WorkerSupervisor::throw_if_abrupt_exit_requested()
{
    std::scoped_lock lock{mutex_};
    if (abrupt_exit_requested_)
        throw InjectedSupervisorFailure{};
}

} // namespace dns::server
