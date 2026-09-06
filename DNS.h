#pragma once

#include "DNS_Cache.h"
#include "FilterUpdateController.h"
#include "WorkerLoop.h"
#include "WorkerRecovery.h"
#include "common/Expected.h"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace dns::server
{
class WorkerSupervisor;
}

struct DNSConfig
{
    size_t   worker_count{1};
    size_t   cache_capacity{Cache::DEFAULT_TOTAL_CAPACITY};
    uint16_t port{5353};
    bool     runtime_updates_enabled{true};

    // Initial startup is all-or-nothing. These settings govern
    // replacement attempts only after the service becomes Active.
    WorkerFailurePolicy       worker_failure_policy{WorkerFailurePolicy::FailService};
    size_t                    restart_max_attempts{3};
    std::chrono::milliseconds restart_initial_backoff{100};
    std::chrono::milliseconds restart_max_backoff{5'000};
    std::chrono::milliseconds restart_stability_window{30'000};

    // Startup input only. DNS stores the compiled immutable snapshot, not this
    // source vector.
    std::vector<std::string>    blocked_domains;
    dns::server::UpstreamConfig upstream{};
};

enum class DNSLifecycleState
{
    Empty,
    Initialized,
    Starting,
    Active,
    Stopping,
    Stopped,
    Failed,
};

enum class DNSHealthState
{
    Healthy,
    Degraded,
    Unavailable,
};

enum class DNSControlRole
{
    None,
    FilterUpdateCoordinator,
    SnapshotReclaimer,
    WorkerSupervisor,
    Worker,
};

enum class DNSStartErrorCode
{
    InvalidLifecycleState,
    Cancelled,
    CoordinatorThreadCreationFailed,
    CoordinatorInitFailed,
    ReclaimerThreadCreationFailed,
    ReclaimerInitFailed,
    SupervisorThreadCreationFailed,
    SupervisorInitFailed,
    WorkerCreateFailed,
    WorkerRuntimeInitFailed,
    WorkerThreadCreationFailed,
    InternalError,
};

struct DNSStartError
{
    DNSStartErrorCode                              code{DNSStartErrorCode::InternalError};
    DNSControlRole                                 role{DNSControlRole::None};
    size_t                                         worker_id{std::numeric_limits<size_t>::max()};
    uint64_t                                       instance_id{0};
    std::optional<dns::server::WorkerInitError>    worker_create_error;
    std::optional<dns::server::WorkerRuntimeError> worker_runtime_error;
    int                                            error_number{0};

    bool operator==(const DNSStartError &) const = default;
};

struct DNSStartInfo
{
    uint16_t effective_bound_port{0};
    size_t   worker_count{0};
    uint64_t startup_attempt_id{0};

    bool operator==(const DNSStartInfo &) const = default;
};

using DNSStartResult = std::expected<DNSStartInfo, DNSStartError>;

enum class DNSServiceExitCode
{
    NotStarted,
    ExplicitStop,
    StartupFailure,
    Fatal,
    TeardownIncomplete,
};

enum class DNSFatalCode
{
    None,
    CoordinatorExited,
    ReclaimerExited,
    GracePeriodStalled,
    SupervisorExited,
    WorkerExited,
    UnexpectedWorkerStop,
    RestartBudgetExhausted,
    WorkerJoinFailed,
    InternalError,
};

struct DNSFatalError
{
    DNSFatalCode                                              code{DNSFatalCode::None};
    DNSControlRole                                            role{DNSControlRole::None};
    size_t                                                    worker_id{std::numeric_limits<size_t>::max()};
    uint64_t                                                  instance_id{0};
    std::optional<dns::server::WorkerRuntimeError>            worker_error;
    std::optional<dns::server::WorkerInitError>               worker_create_error;
    std::optional<dns::server::WorkerFailureCode>             worker_failure_code;
    int                                                       error_number{0};
    std::shared_ptr<const dns::server::FilterGraceDiagnostic> grace_diagnostic;

    bool operator==(const DNSFatalError &other) const
    {
        return code == other.code && role == other.role && worker_id == other.worker_id && instance_id == other.instance_id &&
               worker_error == other.worker_error && worker_create_error == other.worker_create_error &&
               worker_failure_code == other.worker_failure_code && error_number == other.error_number &&
               static_cast<bool>(grace_diagnostic) == static_cast<bool>(other.grace_diagnostic) &&
               (!grace_diagnostic || *grace_diagnostic == *other.grace_diagnostic);
    }
};

struct DNSServiceExitResult
{
    DNSServiceExitCode           code{DNSServiceExitCode::NotStarted};
    std::optional<DNSStartError> startup_error;
    std::optional<DNSFatalError> fatal_error;

    bool operator==(const DNSServiceExitResult &) const = default;
};

struct DNSHealthSnapshot
{
    DNSHealthState                            state{DNSHealthState::Unavailable};
    size_t                                    available_workers{0};
    size_t                                    desired_workers{0};
    uint64_t                                  restart_count{0};
    uint64_t                                  restart_success_count{0};
    uint64_t                                  restart_failure_count{0};
    std::optional<uint16_t>                   effective_bound_port;
    std::optional<dns::server::FilterVersion> filter_version;
    std::optional<DNSFatalError>              last_error;

    bool operator==(const DNSHealthSnapshot &) const = default;
};

struct DNSTestPeer;

class DNS final
{
public:
    DNS();
    ~DNS();

    DNS(const DNS &)            = delete;
    DNS &operator=(const DNS &) = delete;

    bool init(const DNSConfig &config);

    [[nodiscard]] DNSStartResult       start();
    void                               request_stop() noexcept;
    [[nodiscard]] DNSServiceExitResult join() noexcept;
    [[nodiscard]] DNSServiceExitResult wait() noexcept;

    [[nodiscard]] dns::server::FilterUpdateResult replace_blocked_domains(std::vector<std::string> rules);

    [[nodiscard]] bool                                      is_running() const noexcept;
    [[nodiscard]] DNSLifecycleState                         lifecycle_state() const noexcept;
    [[nodiscard]] DNSHealthSnapshot                         health() const noexcept;
    [[nodiscard]] std::optional<uint16_t>                   bound_port() const noexcept;
    [[nodiscard]] std::optional<dns::server::FilterVersion> filter_version() const noexcept;

private:
    friend struct DNSTestPeer;

    enum class StopCause
    {
        None,
        Explicit,
        StartupFailure,
        Fatal,
    };

    struct RuntimeConfig
    {
        size_t                            worker_count{1};
        size_t                            cache_capacity{Cache::DEFAULT_TOTAL_CAPACITY};
        uint16_t                          port{5353};
        bool                              runtime_updates_enabled{true};
        dns::server::WorkerRecoveryConfig recovery{};
        dns::server::UpstreamConfig       upstream{};
    };

    struct ControlPlaneState;
    struct FaultInjection;

    void                               coordinator_main(std::stop_token stop_token, uint64_t attempt_id) noexcept;
    void                               reclaimer_main(std::stop_token stop_token, uint64_t attempt_id) noexcept;
    void                               supervisor_main(std::stop_token stop_token, uint64_t attempt_id) noexcept;
    [[nodiscard]] bool                 accept_fatal_locked(DNSFatalError error) noexcept;
    void                               fail_service(DNSFatalError error) noexcept;
    void                               request_runtime_stop() noexcept;
    [[nodiscard]] DNSServiceExitResult finish_teardown(bool request_explicit_stop) noexcept;
    [[nodiscard]] DNSServiceExitResult exit_result_locked() const noexcept;

    // Deterministic lifecycle seams used only by DNSTestPeer. They remain
    // private so production callers cannot manufacture control-plane faults.
    void               inject_coordinator_thread_failure_for_test() noexcept;
    void               inject_coordinator_init_failure_for_test() noexcept;
    void               inject_coordinator_runtime_failure_for_test() noexcept;
    void               inject_coordinator_postcommit_failure_for_test() noexcept;
    void               inject_reclaimer_thread_failure_for_test() noexcept;
    void               inject_reclaimer_init_failure_for_test() noexcept;
    void               inject_reclaimer_runtime_failure_for_test() noexcept;
    void               inject_reclaimer_postcommit_failure_for_test() noexcept;
    void               inject_supervisor_thread_failure_for_test() noexcept;
    void               inject_supervisor_runtime_failure_for_test() noexcept;
    void               inject_supervisor_postcommit_failure_for_test() noexcept;
    void               inject_worker_create_failure_for_test(size_t worker_id, dns::server::WorkerInitStep step, int error_number) noexcept;
    void               inject_worker_runtime_init_failure_for_test(size_t worker_id) noexcept;
    void               inject_worker_thread_failure_for_test(size_t worker_id) noexcept;
    void               inject_worker_unexpected_stop_for_test(size_t worker_id) noexcept;
    [[nodiscard]] bool inject_worker_precommit_failure_for_test(size_t worker_id) noexcept;
    void               inject_teardown_incomplete_once_for_test() noexcept;
    void               arm_startup_pause_for_test() noexcept;
    void               wait_for_startup_pause_for_test();
    void               release_startup_pause_for_test() noexcept;

    std::mutex                   startup_mutex_;
    std::mutex                   join_mutex_;
    mutable std::mutex           lifecycle_mutex_;
    std::condition_variable      lifecycle_changed_;
    DNSLifecycleState            state_{DNSLifecycleState::Empty};
    bool                         init_in_progress_{false};
    StopCause                    stop_cause_{StopCause::None};
    uint64_t                     startup_attempt_id_{0};
    std::stop_source             startup_stop_source_;
    bool                         update_admission_open_{false};
    RuntimeConfig                config_{};
    DNSHealthSnapshot            health_{};
    std::optional<DNSStartError> startup_error_;
    std::optional<DNSFatalError> fatal_error_;

    std::unique_ptr<ControlPlaneState>                   control_;
    std::unique_ptr<FaultInjection>                      faults_;
    std::unique_ptr<dns::server::FilterUpdateController> filter_updates_;
    std::unique_ptr<Cache::DNS_Cache>                    cache_;
    std::unique_ptr<dns::server::WorkerSupervisor>       supervisor_;
    std::jthread                                         coordinator_thread_;
    std::jthread                                         reclaimer_thread_;
    std::jthread                                         supervisor_thread_;
};
