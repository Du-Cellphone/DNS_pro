#pragma once

#include "DNS_Cache.h"
#include "FilterPublication.h"
#include "WorkerLoop.h"
#include "common/Expected.h"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <thread>
#include <vector>

namespace dns::server
{

inline constexpr size_t kInvalidWorkerId = std::numeric_limits<size_t>::max();

enum class WorkerRecordState : uint8_t
{
    Offline,
    Creating,
    Starting,
    Ready,
    Running,
    Stopping,
    Exited,
    Joined,
};

enum class SupervisorStartupErrorCode : uint8_t
{
    Cancelled,
    InvalidConfiguration,
    InstanceIdExhausted,
    WorkerCreateFailed,
    WorkerThreadStartFailed,
    WorkerInitFailed,
    WorkerExitedBeforeReady,
    InternalError,
};

struct SupervisorStartupError final
{
    SupervisorStartupErrorCode        code{SupervisorStartupErrorCode::InternalError};
    size_t                            worker_id{kInvalidWorkerId};
    uint64_t                          instance_id{0};
    int                               error_number{0};
    std::optional<WorkerInitError>    create_error;
    std::optional<WorkerRuntimeError> runtime_error;

    bool operator==(const SupervisorStartupError &) const = default;
};

struct SupervisorStartupInfo final
{
    uint16_t bound_port{0};
    size_t   worker_count{0};

    bool operator==(const SupervisorStartupInfo &) const = default;
};

using SupervisorStartupResult = std::expected<SupervisorStartupInfo, SupervisorStartupError>;

enum class SupervisorActivationErrorCode : uint8_t
{
    Cancelled,
    WorkerExitedBeforeActivation,
    InternalError,
};

struct SupervisorActivationError final
{
    SupervisorActivationErrorCode  code{SupervisorActivationErrorCode::InternalError};
    size_t                         worker_id{kInvalidWorkerId};
    uint64_t                       instance_id{0};
    std::optional<WorkerRunResult> worker_result;

    bool operator==(const SupervisorActivationError &) const = default;
};

using SupervisorActivationResult = std::expected<void, SupervisorActivationError>;

enum class SupervisorRunOutcome : uint8_t
{
    RequestedStop,
    StartupFailure,
    FatalExit,
};

enum class SupervisorRunErrorCode : uint8_t
{
    None,
    AlreadyRunning,
    UnexpectedWorkerStop,
    WorkerFatalExit,
    InternalError,
};

struct SupervisorRunResult final
{
    SupervisorRunOutcome                  outcome{SupervisorRunOutcome::FatalExit};
    SupervisorRunErrorCode                error_code{SupervisorRunErrorCode::InternalError};
    size_t                                worker_id{kInvalidWorkerId};
    uint64_t                              instance_id{0};
    int                                   error_number{0};
    std::optional<SupervisorStartupError> startup_error;
    std::optional<WorkerRunResult>        worker_result;

    bool operator==(const SupervisorRunResult &) const = default;
};

// Deterministic, allocation-free fault selection used by lifecycle tests. A
// selected runtime-init failure is injected at the Ready boundary: the worker
// is denied activation and stopped without publishing a successful Ready.
struct WorkerSupervisorFaultHooks final
{
    size_t            create_failure_worker{kInvalidWorkerId};
    WorkerInitStep    create_failure_step{WorkerInitStep::CreateSocket};
    int               create_failure_error{0};
    size_t            thread_failure_worker{kInvalidWorkerId};
    int               thread_failure_error{0};
    size_t            runtime_init_failure_worker{kInvalidWorkerId};
    WorkerRuntimeStep runtime_init_failure_step{WorkerRuntimeStep::StartScheduler};
    int               runtime_init_failure_error{0};
};

class WorkerSupervisor;
class WorkerRecordObserver;
struct WorkerSupervisorTestPeer;

// WorkerRecord is the stable logical slot. Its ordinary fields are private and
// have exactly one normal writer: WorkerSupervisor::run(). After that thread is
// joined, emergency_join_all() becomes the sole teardown writer.
class WorkerRecord final
{
public:
    ~WorkerRecord();

    WorkerRecord(const WorkerRecord &)            = delete;
    WorkerRecord &operator=(const WorkerRecord &) = delete;

    [[nodiscard]] size_t             worker_id() const noexcept { return worker_id_; }
    [[nodiscard]] const WorkerEpoch &epoch() const noexcept { return epoch_; }

private:
    friend class WorkerSupervisor;
    friend class WorkerRecordObserver;
    friend struct WorkerSupervisorTestPeer;

    struct ReadySlot final
    {
        bool              published{false};
        uint64_t          instance_id{0};
        WorkerReadyResult result{};
    };

    struct ActivationSlot final
    {
        bool     published{false};
        uint64_t instance_id{0};
    };

    struct CompletionSlot final
    {
        bool            published{false};
        bool            stop_was_requested{false};
        uint64_t        instance_id{0};
        WorkerRunResult result{};
    };

    explicit WorkerRecord(size_t worker_id);

    size_t                                worker_id_{0};
    WorkerRecordState                     state_{WorkerRecordState::Offline};
    uint64_t                              instance_id_{0};
    std::unique_ptr<WorkerLoop>           current_instance_;
    std::jthread                          current_thread_;
    std::stop_source                      instance_stop_source_;
    ReadySlot                             ready_;
    ActivationSlot                        activated_;
    CompletionSlot                        completion_;
    std::optional<WorkerRunResult>        last_result_;
    std::unique_ptr<WorkerRecordObserver> observer_;
    WorkerEpoch                           epoch_;
};

class WorkerSupervisor final : public FilterPublicationSink
{
public:
    using RuntimeFatalReporter = void (*)(void *context, size_t worker_id, uint64_t instance_id, const WorkerRunResult &result) noexcept;

    struct Config final
    {
        size_t                     worker_count{0};
        uint16_t                   requested_port{0};
        Cache::DNS_Cache          *cache{nullptr};
        FilterPublicationState    *filter_publication{nullptr};
        UpstreamConfig             upstream{};
        WorkerSupervisorFaultHooks fault_hooks{};
        void                      *fatal_reporter_context{nullptr};
        RuntimeFatalReporter       fatal_reporter{nullptr};
    };

    explicit WorkerSupervisor(Config config);
    ~WorkerSupervisor();

    WorkerSupervisor(const WorkerSupervisor &)            = delete;
    WorkerSupervisor &operator=(const WorkerSupervisor &) = delete;

    // One-shot C-thread body. Expected startup failures are returned as data;
    // unexpected C failures escape for the DNS top-level thread wrapper.
    [[nodiscard]] SupervisorRunResult run(std::stop_token stop_token);

    [[nodiscard]] SupervisorStartupResult    wait_for_startup(std::stop_token stop_token = {}) noexcept;
    [[nodiscard]] bool                       request_activation() noexcept;
    [[nodiscard]] SupervisorActivationResult wait_for_activation(std::stop_token stop_token = {}) noexcept;
    [[nodiscard]] SupervisorActivationResult release_data_plane() noexcept;

    // Safe from any thread. It only touches stable stop endpoints and the
    // supervisor event predicate, never C-owned WorkerLoop/jthread fields.
    void request_stop() noexcept;

    // A calls only this stable event endpoint. C remains the sole thread that
    // looks up current WorkerLoop instances and writes their generation fds.
    void snapshot_published(FilterGeneration generation) noexcept override;

    // Emergency successor path. The caller must first join the C thread. It
    // returns false if C is still active or a worker thread could not be joined.
    [[nodiscard]] bool emergency_join_all() noexcept;

    // Internal deterministic seams used by lifecycle tests. They enqueue work
    // for the C thread; neither method reads C-owned instance fields.
    void inject_abrupt_exit_for_testing() noexcept;
    void inject_abrupt_exit_after_next_publication_for_testing() noexcept;
    bool inject_worker_unexpected_stop_for_testing(size_t worker_id) noexcept;
    bool inject_worker_precommit_failure_for_testing(size_t worker_id) noexcept;
    void inject_emergency_join_failure_once_for_testing() noexcept;

    [[nodiscard]] size_t             record_count() const noexcept { return records_.size(); }
    [[nodiscard]] const WorkerEpoch &epoch(size_t worker_id) const;

private:
    friend class WorkerRecordObserver;
    friend struct WorkerSupervisorTestPeer;

    [[nodiscard]] SupervisorRunResult                      run_impl(std::stop_token stop_token);
    [[nodiscard]] std::optional<SupervisorStartupError>    create_workers();
    [[nodiscard]] std::optional<SupervisorStartupError>    start_worker_threads();
    [[nodiscard]] std::optional<SupervisorStartupError>    await_worker_readiness();
    [[nodiscard]] std::optional<SupervisorActivationError> await_activation_command_and_workers();
    [[nodiscard]] SupervisorRunResult                      monitor_active_workers();

    void                                        worker_entry(WorkerRecord &record, uint64_t instance_id, std::stop_token thread_stop_token) noexcept;
    void                                        report_worker_ready(WorkerRecord &record, uint64_t instance_id, WorkerReadyResult result) noexcept;
    [[nodiscard]] WorkerRunObserver::GateAction await_worker_activation(WorkerRecord &record, uint64_t instance_id,
                                                                        std::stop_token stop_token) noexcept;
    void                                        report_worker_activated(WorkerRecord &record, uint64_t instance_id) noexcept;
    [[nodiscard]] WorkerRunObserver::GateAction await_worker_data_plane(WorkerRecord &record, uint64_t instance_id,
                                                                        std::stop_token stop_token) noexcept;
    void                                        report_worker_filter_progress(WorkerRecord &record, uint64_t instance_id) noexcept;
    void                                        report_worker_completion(WorkerRecord &record, uint64_t instance_id, WorkerRunResult result) noexcept;

    void               publish_startup(SupervisorStartupResult result) noexcept;
    void               publish_activation(SupervisorActivationResult result) noexcept;
    void               publish_abrupt_failure() noexcept;
    void               finish_run() noexcept;
    void               request_all_worker_stops() noexcept;
    [[nodiscard]] bool join_and_reset_all() noexcept;
    [[nodiscard]] bool join_and_reset(WorkerRecord &record) noexcept;

    [[nodiscard]] bool          stop_requested_locked() const noexcept { return stop_requested_; }
    [[nodiscard]] bool          has_unconsumed_completion_locked() const noexcept;
    [[nodiscard]] WorkerRecord *first_unconsumed_completion_locked() noexcept;
    void                        throw_if_abrupt_exit_requested();

    Config                                     config_;
    std::vector<std::unique_ptr<WorkerRecord>> records_;
    mutable std::mutex                         mutex_;
    std::condition_variable_any                wakeup_;
    std::optional<SupervisorStartupResult>     startup_result_;
    std::optional<SupervisorActivationResult>  activation_result_;
    bool                                       activation_requested_{false};
    bool                                       data_plane_released_{false};
    bool                                       stop_requested_{false};
    bool                                       run_started_{false};
    bool                                       abrupt_exit_requested_{false};
    bool                                       abrupt_exit_after_publication_requested_{false};
    bool                                       emergency_join_failure_once_{false};
    std::optional<size_t>                      unexpected_stop_worker_;
    FilterGeneration                           published_generation_{kInitialFilterGeneration};
    bool                                       snapshot_publication_pending_{false};
    std::atomic<bool>                          run_active_{false};
};

} // namespace dns::server
