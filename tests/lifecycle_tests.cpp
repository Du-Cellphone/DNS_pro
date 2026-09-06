#include "DNS.h"
#include "WorkerSupervisor.h"
#include "runtime/UniqueFd.h"
#include "tests/SocketTestSupport.h"

#include <array>
#include <barrier>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <semaphore>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <utility>

namespace dns::server
{

struct WorkerSupervisorTestPeer
{
    static SupervisorActivationResult release_after_completion(uint64_t reported_instance_id)
    {
        WorkerSupervisor supervisor{WorkerSupervisor::Config{.worker_count = 1}};
        WorkerRecord    &record = *supervisor.records_.front();
        {
            std::scoped_lock lock{supervisor.mutex_};
            supervisor.run_started_ = true;
            supervisor.run_active_.store(true, std::memory_order_release);
            supervisor.activation_result_.emplace(SupervisorActivationResult{});
            record.instance_id_ = 2;
            record.state_       = WorkerRecordState::Running;
        }

        const WorkerRunResult failure{WorkerRunOutcome::FatalExit, WorkerRuntimeError{WorkerRuntimeStep::AwaitActivation, EIO}};
        supervisor.report_worker_completion(record, reported_instance_id, failure);
        auto released = supervisor.release_data_plane();
        supervisor.run_active_.store(false, std::memory_order_release);
        return released;
    }
};

} // namespace dns::server

struct DNSTestPeer
{
    static void fail_coordinator_thread(DNS &service) noexcept { service.inject_coordinator_thread_failure_for_test(); }
    static void fail_coordinator_init(DNS &service) noexcept { service.inject_coordinator_init_failure_for_test(); }
    static void fail_coordinator_runtime(DNS &service) noexcept { service.inject_coordinator_runtime_failure_for_test(); }
    static void fail_coordinator_after_commit(DNS &service) noexcept { service.inject_coordinator_postcommit_failure_for_test(); }
    static void fail_reclaimer_thread(DNS &service) noexcept { service.inject_reclaimer_thread_failure_for_test(); }
    static void fail_reclaimer_init(DNS &service) noexcept { service.inject_reclaimer_init_failure_for_test(); }
    static void fail_reclaimer_runtime(DNS &service) noexcept { service.inject_reclaimer_runtime_failure_for_test(); }
    static void fail_reclaimer_after_commit(DNS &service) noexcept { service.inject_reclaimer_postcommit_failure_for_test(); }
    static void fail_supervisor_thread(DNS &service) noexcept { service.inject_supervisor_thread_failure_for_test(); }
    static void fail_supervisor_runtime(DNS &service) noexcept { service.inject_supervisor_runtime_failure_for_test(); }
    static void fail_supervisor_after_commit(DNS &service) noexcept { service.inject_supervisor_postcommit_failure_for_test(); }

    static void fail_worker_create(DNS &service, size_t worker_id, dns::server::WorkerInitStep step, int error_number) noexcept
    {
        service.inject_worker_create_failure_for_test(worker_id, step, error_number);
    }

    static void fail_worker_runtime_init(DNS &service, size_t worker_id) noexcept { service.inject_worker_runtime_init_failure_for_test(worker_id); }

    static void fail_worker_thread(DNS &service, size_t worker_id) noexcept { service.inject_worker_thread_failure_for_test(worker_id); }

    static void stop_worker_unexpectedly(DNS &service, size_t worker_id) noexcept { service.inject_worker_unexpected_stop_for_test(worker_id); }
    static bool fail_worker_precommit(DNS &service, size_t worker_id) noexcept { return service.inject_worker_precommit_failure_for_test(worker_id); }
    static void fail_emergency_join_once(DNS &service) noexcept { service.inject_teardown_incomplete_once_for_test(); }

    static void arm_startup_pause(DNS &service) noexcept { service.arm_startup_pause_for_test(); }
    static void wait_for_startup_pause(DNS &service) { service.wait_for_startup_pause_for_test(); }
    static void release_startup_pause(DNS &service) noexcept { service.release_startup_pause_for_test(); }

    static void report_runtime_fatal(DNS &service, DNSFatalCode code, DNSControlRole role) noexcept
    {
        DNSFatalError error;
        error.code = code;
        error.role = role;
        service.fail_service(std::move(error));
    }
};

namespace
{

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "lifecycle test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

DNSConfig make_config(size_t worker_count = 1, bool runtime_updates_enabled = true)
{
    DNSConfig config;
    config.worker_count            = worker_count;
    config.runtime_updates_enabled = runtime_updates_enabled;
    config.cache_capacity          = 16;
    config.port                    = 0;
    return config;
}

void require_update_error(const dns::server::FilterUpdateResult &result, dns::server::FilterUpdateErrorCode expected, std::string_view message)
{
    require(!result && result.error().code == expected, message);
}

void require_start_error(const DNSStartResult &result, DNSStartErrorCode expected_code, DNSControlRole expected_role, std::string_view message)
{
    require(!result && result.error().code == expected_code && result.error().role == expected_role, message);
}

void require_startup_failure_terminal(DNS &service, const DNSStartResult &start_result, DNSStartErrorCode expected_code, DNSControlRole expected_role,
                                      std::string_view message)
{
    require_start_error(start_result, expected_code, expected_role, message);
    require(service.lifecycle_state() == DNSLifecycleState::Failed && !service.is_running(),
            "a failed startup must finish rollback in the terminal Failed state");
    require(!service.bound_port(), "a failed startup must not publish its attempt-local bound port");

    const auto exit = service.join();
    require(exit.code == DNSServiceExitCode::StartupFailure && exit.startup_error && exit.startup_error->code == expected_code &&
                exit.startup_error->role == expected_role,
            "join must retain the typed startup failure after rollback");

    auto second_start = service.start();
    require(!second_start && second_start.error().code == DNSStartErrorCode::InvalidLifecycleState,
            "a Failed DNS object must reject another start attempt");
    require(!service.init(make_config()), "a Failed DNS object must reject re-initialization");
}

DNSServiceExitResult wait_for_fatal(DNS &service, DNSFatalCode expected_code, DNSControlRole expected_role, std::string_view message)
{
    const auto exit = service.wait();
    require(exit.code == DNSServiceExitCode::Fatal && exit.fatal_error && exit.fatal_error->code == expected_code &&
                exit.fatal_error->role == expected_role,
            message);
    require(service.lifecycle_state() == DNSLifecycleState::Failed && !service.is_running(),
            "fatal teardown must finish in Failed rather than pretending to be an explicit stop");

    const auto health = service.health();
    require(health.state == DNSHealthState::Unavailable && health.available_workers == 0 && health.last_error == exit.fatal_error,
            "fatal teardown must publish an unavailable health snapshot containing the first fatal error");
    require(service.join() == exit, "join after wait must return the same immutable fatal result");
    return exit;
}

void test_unique_fd_ownership()
{
    int pipe_fds[2]{-1, -1};
    require(::pipe2(pipe_fds, O_CLOEXEC) == 0, "pipe fixture must be created");
    const int observed_fd = pipe_fds[0];

    {
        dns::runtime::UniqueFd read_end{pipe_fds[0]};
        dns::runtime::UniqueFd moved{std::move(read_end)};
        require(!read_end && moved.get() == observed_fd, "moving UniqueFd must transfer sole ownership");

        const int released = moved.release();
        require(!moved && released == observed_fd, "release must return ownership without closing");
        require(::close(released) == 0, "released descriptor must remain open for the caller");
    }

    errno = 0;
    require(::fcntl(observed_fd, F_GETFD) == -1 && errno == EBADF, "released descriptor must be closed exactly once by its new owner");
    ::close(pipe_fds[1]);

    require(::pipe2(pipe_fds, O_CLOEXEC) == 0, "second pipe fixture must be created");
    const int automatically_closed = pipe_fds[0];
    {
        dns::runtime::UniqueFd owned{automatically_closed};
    }
    errno = 0;
    require(::fcntl(automatically_closed, F_GETFD) == -1 && errno == EBADF, "UniqueFd destructor must close an owned descriptor");
    ::close(pipe_fds[1]);
}

void test_init_retry_second_init_and_initialized_stop()
{
    DNS service;
    require(service.lifecycle_state() == DNSLifecycleState::Empty, "a new service must begin Empty");
    require_update_error(service.replace_blocked_domains({"empty.example"}), dns::server::FilterUpdateErrorCode::ServiceNotRunning,
                         "an Empty service must reject runtime updates");

    DNSConfig invalid    = make_config();
    invalid.worker_count = 0;
    require(!service.init(invalid) && service.lifecycle_state() == DNSLifecycleState::Empty,
            "configuration validation failure must leave the object Empty and retryable");

    invalid                 = make_config();
    invalid.blocked_domains = {"*.invalid.example"};
    require(!service.init(invalid) && service.lifecycle_state() == DNSLifecycleState::Empty,
            "initial filter compilation failure must also leave the object Empty");

    invalid                         = make_config();
    invalid.upstream.query_timeout  = std::chrono::seconds{5};
    invalid.upstream.id_reuse_guard = std::chrono::seconds{1};
    require(!service.init(invalid) && service.lifecycle_state() == DNSLifecycleState::Empty,
            "an invalid upstream timeout/ID-reuse relation must leave the object Empty");

    invalid                       = make_config();
    invalid.worker_failure_policy = WorkerFailurePolicy::Restart;
    invalid.restart_max_attempts  = 0;
    require(!service.init(invalid) && service.lifecycle_state() == DNSLifecycleState::Empty, "Restart policy must reject a zero recovery budget");

    invalid                         = make_config();
    invalid.worker_failure_policy   = WorkerFailurePolicy::Restart;
    invalid.restart_initial_backoff = std::chrono::milliseconds{20};
    invalid.restart_max_backoff     = std::chrono::milliseconds{10};
    require(!service.init(invalid) && service.lifecycle_state() == DNSLifecycleState::Empty,
            "Restart policy must reject a maximum backoff below its initial backoff");

    invalid                         = make_config();
    invalid.worker_failure_policy   = WorkerFailurePolicy::Restart;
    invalid.restart_initial_backoff = std::chrono::milliseconds{-1};
    require(!service.init(invalid) && service.lifecycle_state() == DNSLifecycleState::Empty, "Restart policy must reject a negative initial backoff");

    invalid                          = make_config();
    invalid.worker_failure_policy    = WorkerFailurePolicy::Restart;
    invalid.restart_stability_window = std::chrono::milliseconds{-1};
    require(!service.init(invalid) && service.lifecycle_state() == DNSLifecycleState::Empty,
            "Restart policy must reject a negative stability window");

    invalid                       = make_config();
    invalid.worker_failure_policy = static_cast<WorkerFailurePolicy>(99);
    require(!service.init(invalid) && service.lifecycle_state() == DNSLifecycleState::Empty, "an unknown worker failure policy must be rejected");

    const DNSConfig valid = make_config();
    require(service.init(valid), "the same object must accept a corrected configuration after init failure");
    require(service.lifecycle_state() == DNSLifecycleState::Initialized &&
                service.filter_version() == std::optional{dns::server::FilterVersion{1, 0}},
            "successful init must publish generation one and enter Initialized");
    require(!service.init(valid), "a successfully initialized object must reject a second init call");
    require_update_error(service.replace_blocked_domains({"initialized.example"}), dns::server::FilterUpdateErrorCode::ServiceNotRunning,
                         "update admission must remain closed while Initialized");

    service.request_stop();
    require(service.lifecycle_state() == DNSLifecycleState::Stopped && !service.is_running(),
            "stopping an Initialized service must abandon it into terminal Stopped");
    require(service.join().code == DNSServiceExitCode::ExplicitStop, "join after abandoning Initialized must report ExplicitStop");
    require_update_error(service.replace_blocked_domains({"stopped.example"}), dns::server::FilterUpdateErrorCode::ShuttingDown,
                         "a Stopped service must reject updates immediately");

    auto start_after_stop = service.start();
    require(!start_after_stop && start_after_stop.error().code == DNSStartErrorCode::InvalidLifecycleState,
            "Stopped is terminal and must reject start");
    require(!service.init(valid), "Stopped is terminal and must reject re-initialization");
}

void test_typed_worker_create_failure_after_partial_creation()
{
    DNS service;
    require(service.init(make_config(2, false)), "worker-create failure fixture must initialize");
    DNSTestPeer::fail_worker_create(service, 1, dns::server::WorkerInitStep::BindSocket, EADDRINUSE);

    const auto started = service.start();
    require_start_error(started, DNSStartErrorCode::WorkerCreateFailed, DNSControlRole::Worker,
                        "the injected worker create failure must reach DNS::start as structured data");
    require(started.error().worker_id == 1 && started.error().instance_id == 1 && started.error().error_number == EADDRINUSE &&
                started.error().worker_create_error ==
                    std::optional{dns::server::WorkerInitError{dns::server::WorkerInitStep::BindSocket, EADDRINUSE}},
            "worker create errors must retain the exact worker, instance, init step, and errno");
    require_startup_failure_terminal(service, started, DNSStartErrorCode::WorkerCreateFailed, DNSControlRole::Worker,
                                     "worker create failure must be terminal");
}

void test_all_worker_create_steps_remain_typed()
{
    constexpr std::array steps{
        dns::server::WorkerInitStep::CreateSocket,      dns::server::WorkerInitStep::ConfigureSocket,
        dns::server::WorkerInitStep::BindSocket,        dns::server::WorkerInitStep::ReadBoundAddress,
        dns::server::WorkerInitStep::CreateEpoll,       dns::server::WorkerInitStep::CreateWakeEvent,
        dns::server::WorkerInitStep::ValidateUpstream,  dns::server::WorkerInitStep::CreateUpstreamSocket,
        dns::server::WorkerInitStep::ConnectUpstream,   dns::server::WorkerInitStep::RegisterListener,
        dns::server::WorkerInitStep::RegisterWakeEvent, dns::server::WorkerInitStep::RegisterUpstream,
    };

    for (const auto step : steps)
    {
        DNS service;
        require(service.init(make_config(1, false)), "worker-create step fixture must initialize");
        DNSTestPeer::fail_worker_create(service, 0, step, EIO);

        const auto started = service.start();
        require(!started && started.error().code == DNSStartErrorCode::WorkerCreateFailed &&
                    started.error().worker_create_error == std::optional{dns::server::WorkerInitError{step, EIO}} &&
                    started.error().error_number == EIO,
                "every worker create step must survive supervisor and DNS startup mapping");
        require(service.join().code == DNSServiceExitCode::StartupFailure, "every injected worker create step must complete startup rollback");
    }
}

void test_typed_worker_runtime_init_failure()
{
    DNS service;
    require(service.init(make_config(1, false)), "worker runtime-init failure fixture must initialize");
    DNSTestPeer::fail_worker_runtime_init(service, 0);

    const auto started = service.start();
    require_start_error(started, DNSStartErrorCode::WorkerRuntimeInitFailed, DNSControlRole::Worker,
                        "a worker failure before Ready must fail the complete startup");
    require(started.error().worker_id == 0 && started.error().instance_id == 1 && started.error().worker_runtime_error &&
                started.error().worker_runtime_error->step == dns::server::WorkerRuntimeStep::StartScheduler &&
                started.error().worker_runtime_error->error_number == EIO,
            "worker runtime-init failure must retain its typed step and errno");
    require_startup_failure_terminal(service, started, DNSStartErrorCode::WorkerRuntimeInitFailed, DNSControlRole::Worker,
                                     "worker runtime-init failure must be terminal");
}

void test_typed_worker_thread_failure_after_partial_start()
{
    DNS service;
    require(service.init(make_config(2, false)), "worker-thread failure fixture must initialize");
    DNSTestPeer::fail_worker_thread(service, 1);

    const auto started = service.start();
    require_start_error(started, DNSStartErrorCode::WorkerThreadCreationFailed, DNSControlRole::Worker,
                        "the Kth worker thread creation failure must reach DNS::start");
    require(started.error().worker_id == 1 && started.error().instance_id == 1 && started.error().error_number == EAGAIN,
            "thread creation failure must identify the exact logical worker and instance");
    require_startup_failure_terminal(service, started, DNSStartErrorCode::WorkerThreadCreationFailed, DNSControlRole::Worker,
                                     "worker thread creation failure must be terminal");
}

void test_typed_control_role_start_failures()
{
    {
        std::cerr << "  injecting reclaimer thread creation failure\n";
        DNS service;
        require(service.init(make_config()), "reclaimer-thread failure fixture must initialize");
        DNSTestPeer::fail_reclaimer_thread(service);
        const auto started = service.start();
        require(!started && started.error().error_number == EAGAIN, "injected reclaimer thread failure must retain EAGAIN");
        require_startup_failure_terminal(service, started, DNSStartErrorCode::ReclaimerThreadCreationFailed, DNSControlRole::SnapshotReclaimer,
                                         "reclaimer thread creation failure must be typed and terminal");
    }
    {
        std::cerr << "  injecting reclaimer Ready failure\n";
        DNS service;
        require(service.init(make_config()), "reclaimer-init failure fixture must initialize");
        DNSTestPeer::fail_reclaimer_init(service);
        const auto started = service.start();
        require_startup_failure_terminal(service, started, DNSStartErrorCode::ReclaimerInitFailed, DNSControlRole::SnapshotReclaimer,
                                         "reclaimer Ready failure must be typed and terminal");
    }
    {
        std::cerr << "  injecting coordinator thread creation failure\n";
        DNS service;
        require(service.init(make_config()), "coordinator-thread failure fixture must initialize");
        DNSTestPeer::fail_coordinator_thread(service);
        const auto started = service.start();
        require(!started && started.error().error_number == EAGAIN, "injected coordinator thread failure must retain EAGAIN");
        require_startup_failure_terminal(service, started, DNSStartErrorCode::CoordinatorThreadCreationFailed,
                                         DNSControlRole::FilterUpdateCoordinator, "coordinator thread creation failure must be typed and terminal");
    }
    {
        std::cerr << "  injecting coordinator Ready failure\n";
        DNS service;
        require(service.init(make_config()), "coordinator-init failure fixture must initialize");
        DNSTestPeer::fail_coordinator_init(service);
        const auto started = service.start();
        require_startup_failure_terminal(service, started, DNSStartErrorCode::CoordinatorInitFailed, DNSControlRole::FilterUpdateCoordinator,
                                         "coordinator Ready failure must be typed and terminal");
    }
    {
        std::cerr << "  injecting supervisor thread creation failure\n";
        DNS service;
        require(service.init(make_config()), "supervisor-thread failure fixture must initialize");
        DNSTestPeer::fail_supervisor_thread(service);
        const auto started = service.start();
        require(!started && started.error().error_number == EAGAIN, "injected supervisor thread failure must retain EAGAIN");
        require_startup_failure_terminal(service, started, DNSStartErrorCode::SupervisorThreadCreationFailed, DNSControlRole::WorkerSupervisor,
                                         "supervisor thread creation failure must be typed and terminal");
    }
}

void test_multiworker_port_snapshot_updates_and_concurrent_join()
{
    DNS service;
    require(service.init(make_config(2, true)), "multi-worker lifecycle fixture must initialize");
    require(!service.bound_port(), "the attempt-local port must remain unpublished before Active");

    const auto started = service.start();
    require(static_cast<bool>(started), "a two-worker port-zero service must start after the socket capability probe");
    require(started->worker_count == 2 && started->effective_bound_port != 0 && started->startup_attempt_id == 1,
            "successful start must return the complete immutable startup snapshot");
    require(service.lifecycle_state() == DNSLifecycleState::Active && service.is_running() &&
                service.bound_port() == std::optional{started->effective_bound_port},
            "Active must publish the effective port exactly once");

    const auto health = service.health();
    require(health.state == DNSHealthState::Healthy && health.available_workers == 2 && health.desired_workers == 2 &&
                health.effective_bound_port == service.bound_port(),
            "the Active health snapshot must report every Ready worker and the frozen port");

    auto duplicate_start = service.start();
    require(!duplicate_start && duplicate_start.error().code == DNSStartErrorCode::InvalidLifecycleState && service.is_running(),
            "a duplicate start must be rejected without perturbing the Active attempt");

    auto update = service.replace_blocked_domains({"blocked.example"});
    require(update && update->generation == 2 && update->rule_count == 1, "start must return only after runtime-update admission is ready");

    const uint16_t frozen_port = *service.bound_port();
    service.request_stop();

    std::barrier                        join_gate{3};
    std::optional<DNSServiceExitResult> first_exit;
    std::optional<DNSServiceExitResult> second_exit;
    std::jthread                        first_joiner{[&]
                              {
                                  join_gate.arrive_and_wait();
                                  first_exit = service.join();
                              }};
    std::jthread                        second_joiner{[&]
                               {
                                   join_gate.arrive_and_wait();
                                   second_exit = service.join();
                               }};
    join_gate.arrive_and_wait();
    first_joiner.join();
    second_joiner.join();

    require(first_exit && second_exit && *first_exit == *second_exit && first_exit->code == DNSServiceExitCode::ExplicitStop,
            "concurrent joiners must observe the same structured ExplicitStop result");
    require(service.lifecycle_state() == DNSLifecycleState::Stopped && service.bound_port() == std::optional{frozen_port},
            "normal teardown must retain the immutable effective port snapshot");
    require(service.filter_version() == std::optional{dns::server::FilterVersion{2, 1}},
            "teardown must retain non-owning metadata for the final filter generation");
    require_update_error(service.replace_blocked_domains({"late.example"}), dns::server::FilterUpdateErrorCode::ShuttingDown,
                         "update admission must close before normal teardown begins");
}

void test_concurrent_start_accepts_exactly_one_attempt()
{
    DNS service;
    require(service.init(make_config(2, false)), "concurrent-start fixture must initialize");

    std::barrier                  start_gate{3};
    std::optional<DNSStartResult> first_result;
    std::optional<DNSStartResult> second_result;
    std::jthread                  first_starter{[&]
                               {
                                   start_gate.arrive_and_wait();
                                   first_result.emplace(service.start());
                               }};
    std::jthread                  second_starter{[&]
                                {
                                    start_gate.arrive_and_wait();
                                    second_result.emplace(service.start());
                                }};
    start_gate.arrive_and_wait();
    first_starter.join();
    second_starter.join();

    require(first_result && second_result, "both concurrent start callers must complete");
    const bool first_succeeded  = static_cast<bool>(*first_result);
    const bool second_succeeded = static_cast<bool>(*second_result);
    require(first_succeeded != second_succeeded, "exactly one concurrent start caller must own the startup attempt");

    const auto &successful = first_succeeded ? *first_result : *second_result;
    const auto &rejected   = first_succeeded ? *second_result : *first_result;
    require(successful->startup_attempt_id == 1 && successful->worker_count == 2 && successful->effective_bound_port != 0,
            "the accepted concurrent caller must publish the sole startup resource set");
    require(!rejected && rejected.error().code == DNSStartErrorCode::InvalidLifecycleState,
            "the losing concurrent caller must be rejected without beginning a second attempt");
    require(service.health().available_workers == 2 && service.bound_port() == std::optional{successful->effective_bound_port},
            "concurrent start must leave one healthy two-worker service and one frozen port");

    service.request_stop();
    require(service.join().code == DNSServiceExitCode::ExplicitStop, "the sole concurrent startup attempt must stop cleanly");
}

void test_starting_can_be_cancelled_and_joined()
{
    DNS service;
    require(service.init(make_config(2, false)), "Starting-cancellation fixture must initialize");
    DNSTestPeer::arm_startup_pause(service);

    std::optional<DNSStartResult>       start_result;
    std::optional<DNSServiceExitResult> exit_result;
    std::jthread                        starter{[&] { start_result.emplace(service.start()); }};

    DNSTestPeer::wait_for_startup_pause(service);
    require(service.lifecycle_state() == DNSLifecycleState::Starting && !service.bound_port(),
            "a paused startup must expose Starting without publishing its attempt-local port");
    require_update_error(service.replace_blocked_domains({"starting.example"}), dns::server::FilterUpdateErrorCode::ServiceNotRunning,
                         "runtime update admission must remain closed throughout Starting");

    std::jthread joiner{[&] { exit_result.emplace(service.join()); }};
    joiner.join();
    starter.join();

    require(start_result && !*start_result && start_result->error().code == DNSStartErrorCode::Cancelled,
            "request_stop from join must cancel the exact startup attempt");
    require(exit_result && exit_result->code == DNSServiceExitCode::ExplicitStop && service.lifecycle_state() == DNSLifecycleState::Stopped,
            "join must wait for startup rollback and finish with the first Explicit stop cause");
}

void test_supervisor_rejects_precommit_completion_and_stale_instance()
{
    const auto stale = dns::server::WorkerSupervisorTestPeer::release_after_completion(1);
    require(static_cast<bool>(stale), "a stale completion from an older instance must not block the current data-plane release");

    const auto exact = dns::server::WorkerSupervisorTestPeer::release_after_completion(2);
    require(!exact && exact.error().code == dns::server::SupervisorActivationErrorCode::WorkerExitedBeforeActivation &&
                exact.error().worker_id == 0 && exact.error().instance_id == 2 && exact.error().worker_result &&
                exact.error().worker_result->error ==
                    std::optional{dns::server::WorkerRuntimeError{dns::server::WorkerRuntimeStep::AwaitActivation, EIO}},
            "an exact pre-commit completion must prevent Active and retain the structured worker error");
}

void test_dns_rolls_back_exact_precommit_worker_failure()
{
    DNS service;
    require(service.init(make_config(1, false)), "pre-commit worker-failure fixture must initialize");
    DNSTestPeer::arm_startup_pause(service);

    std::optional<DNSStartResult> start_result;
    std::jthread                  starter{[&] { start_result.emplace(service.start()); }};
    DNSTestPeer::wait_for_startup_pause(service);

    require(service.lifecycle_state() == DNSLifecycleState::Starting && !service.bound_port(),
            "all activated workers must remain hidden behind the data-plane gate before commit");
    require(DNSTestPeer::fail_worker_precommit(service, 0), "the exact current worker must accept a deterministic pre-commit completion");
    DNSTestPeer::release_startup_pause(service);
    starter.join();

    require(start_result && !*start_result && start_result->error().code == DNSStartErrorCode::WorkerRuntimeInitFailed &&
                start_result->error().role == DNSControlRole::Worker && start_result->error().worker_id == 0 &&
                start_result->error().instance_id == 1 &&
                start_result->error().worker_runtime_error ==
                    std::optional{dns::server::WorkerRuntimeError{dns::server::WorkerRuntimeStep::AwaitActivation, EIO}},
            "a worker completion before data-plane release must remain a typed startup failure");
    require(service.lifecycle_state() == DNSLifecycleState::Failed && !service.bound_port(),
            "pre-commit worker failure must roll back the service without publishing its port");
    require(service.join().code == DNSServiceExitCode::StartupFailure, "join must retain StartupFailure after the pre-commit worker rollback");
}

void test_teardown_incomplete_retains_owners_and_can_retry()
{
    DNS service;
    require(service.init(make_config(1, false)), "teardown-incomplete fixture must initialize");
    const auto started = service.start();
    require(static_cast<bool>(started), "teardown-incomplete fixture must become Active");
    const auto frozen_port = service.bound_port();

    DNSTestPeer::fail_emergency_join_once(service);
    service.request_stop();
    const auto incomplete = service.join();
    require(incomplete.code == DNSServiceExitCode::TeardownIncomplete && service.lifecycle_state() == DNSLifecycleState::Stopping &&
                !service.is_running(),
            "an unproven join must retain a nonterminal Stopping service");
    require(service.health().state == DNSHealthState::Unavailable && service.bound_port() == frozen_port && service.filter_version(),
            "TeardownIncomplete must retain owners and immutable service metadata for a retry");

    const auto completed = service.join();
    require(completed.code == DNSServiceExitCode::ExplicitStop && service.lifecycle_state() == DNSLifecycleState::Stopped,
            "a later successful join must complete the retained teardown exactly once");
}

void test_runtime_updates_disabled_do_not_start_coordinator()
{
    DNS service;
    require(service.init(make_config(1, false)), "disabled-update fixture must initialize");
    DNSTestPeer::fail_coordinator_thread(service);
    DNSTestPeer::fail_reclaimer_thread(service);

    const auto started = service.start();
    require(static_cast<bool>(started), "a disabled coordinator must not consume its injected thread failure");
    require_update_error(service.replace_blocked_domains({"disabled.example"}), dns::server::FilterUpdateErrorCode::ControlPlaneDisabled,
                         "an Active service with runtime updates disabled must report ControlPlaneDisabled");

    service.request_stop();
    require(service.join().code == DNSServiceExitCode::ExplicitStop, "a service without coordinator A must still stop through supervisor C cleanly");
}

void test_reclaimer_runtime_fatal()
{
    DNS service;
    require(service.init(make_config()), "reclaimer runtime-fatal fixture must initialize");
    const auto started = service.start();
    require(static_cast<bool>(started), "reclaimer runtime-fatal fixture must become Active");

    DNSTestPeer::fail_reclaimer_runtime(service);
    wait_for_fatal(service, DNSFatalCode::ReclaimerExited, DNSControlRole::SnapshotReclaimer,
                   "an unexpected reclaimer exit must fail the service without dropping stable owners");
}

void test_coordinator_runtime_fatal()
{
    DNS service;
    require(service.init(make_config()), "coordinator runtime-fatal fixture must initialize");
    const auto started = service.start();
    require(static_cast<bool>(started), "coordinator runtime-fatal fixture must become Active");
    const auto frozen_port = service.bound_port();

    DNSTestPeer::fail_coordinator_runtime(service);
    wait_for_fatal(service, DNSFatalCode::CoordinatorExited, DNSControlRole::FilterUpdateCoordinator,
                   "an unexpected coordinator exit must fail the whole service");
    require(service.bound_port() == frozen_port, "fatal teardown must not erase an already committed effective port");
    require(!service.init(make_config()), "a runtime-failed DNS object must not be reusable");
}

void test_supervisor_runtime_fatal()
{
    DNS service;
    require(service.init(make_config(1, false)), "supervisor runtime-fatal fixture must initialize");
    const auto started = service.start();
    require(static_cast<bool>(started), "supervisor runtime-fatal fixture must become Active");

    DNSTestPeer::fail_supervisor_runtime(service);
    wait_for_fatal(service, DNSFatalCode::SupervisorExited, DNSControlRole::WorkerSupervisor,
                   "an unexpected supervisor exit must use the independent fatal-stop path");
}

void test_committed_update_survives_control_role_failures()
{
    const auto exercise = [](auto inject_failure, auto validate_fatal, std::string_view fixture_name)
    {
        DNS service;
        require(service.init(make_config(2, true)), "committed-failure fixture must initialize");
        require(static_cast<bool>(service.start()), "committed-failure fixture must become Active");
        inject_failure(service);

        std::optional<dns::server::FilterUpdateResult> update_result;
        std::jthread updater{[&] { update_result.emplace(service.replace_blocked_domains({"survives-control-failure.example"})); }};

        const auto exit = service.wait();
        updater.join();
        require(exit.code == DNSServiceExitCode::Fatal && exit.fatal_error && validate_fatal(*exit.fatal_error), fixture_name);
        require(update_result && *update_result && update_result->value().generation == 2 && update_result->value().rule_count == 1,
                "an update committed before a control-role failure must complete as success after its exact cohort converges");
        require(service.filter_version() == std::optional{dns::server::FilterVersion{2, 1}},
                "fatal teardown must retain the committed generation's coherent metadata");
    };

    exercise([](DNS &service) { DNSTestPeer::fail_coordinator_after_commit(service); }, [](const DNSFatalError &error)
             { return error.code == DNSFatalCode::CoordinatorExited && error.role == DNSControlRole::FilterUpdateCoordinator; },
             "a postcommit A failure must be classified as a coordinator fatal");

    exercise([](DNS &service) { DNSTestPeer::fail_reclaimer_after_commit(service); },
             [](const DNSFatalError &error)
             {
                 return (error.code == DNSFatalCode::ReclaimerExited && error.role == DNSControlRole::SnapshotReclaimer) ||
                        (error.code == DNSFatalCode::CoordinatorExited && error.role == DNSControlRole::FilterUpdateCoordinator);
             },
             "a postcommit B failure must enter the fatal emergency-reclaimer path");

    exercise([](DNS &service) { DNSTestPeer::fail_supervisor_after_commit(service); }, [](const DNSFatalError &error)
             { return error.code == DNSFatalCode::SupervisorExited && error.role == DNSControlRole::WorkerSupervisor; },
             "a postcommit C failure must be classified as a supervisor fatal");
}

void test_explicit_stop_and_runtime_fatal_are_first_wins()
{
    {
        DNS service;
        require(service.init(make_config(1, false)), "explicit-first fixture must initialize");
        const auto started = service.start();
        require(static_cast<bool>(started), "explicit-first fixture must become Active");

        std::binary_semaphore explicit_done{0};
        std::jthread          stopper{[&]
                             {
                                 service.request_stop();
                                 explicit_done.release();
                             }};
        std::jthread          fatal_reporter{[&]
                                    {
                                        explicit_done.acquire();
                                        DNSTestPeer::report_runtime_fatal(service, DNSFatalCode::SupervisorExited, DNSControlRole::WorkerSupervisor);
                                    }};
        stopper.join();
        fatal_reporter.join();
        const auto exit = service.join();
        require(exit.code == DNSServiceExitCode::ExplicitStop && !exit.fatal_error && service.lifecycle_state() == DNSLifecycleState::Stopped,
                "a fatal report arriving after explicit stop must not overwrite the first stop cause");
    }
    {
        DNS service;
        require(service.init(make_config(1, false)), "fatal-first fixture must initialize");
        const auto started = service.start();
        require(static_cast<bool>(started), "fatal-first fixture must become Active");

        std::binary_semaphore fatal_done{0};
        std::jthread          fatal_reporter{[&]
                                    {
                                        DNSTestPeer::report_runtime_fatal(service, DNSFatalCode::SupervisorExited, DNSControlRole::WorkerSupervisor);
                                        fatal_done.release();
                                    }};
        std::jthread          stopper{[&]
                             {
                                 fatal_done.acquire();
                                 service.request_stop();
                             }};
        fatal_reporter.join();
        stopper.join();
        const auto exit = service.join();
        require(exit.code == DNSServiceExitCode::Fatal && exit.fatal_error && exit.fatal_error->code == DNSFatalCode::SupervisorExited &&
                    exit.fatal_error->role == DNSControlRole::WorkerSupervisor && service.lifecycle_state() == DNSLifecycleState::Failed,
                "an explicit stop arriving after a fatal report must not overwrite the first stop cause");
    }
}

void test_fail_service_policy_preserves_worker_failure()
{
    DNS       service;
    DNSConfig config                = make_config(1, false);
    config.worker_failure_policy    = WorkerFailurePolicy::FailService;
    config.restart_max_attempts     = 5;
    config.restart_initial_backoff  = std::chrono::milliseconds{1};
    config.restart_max_backoff      = std::chrono::milliseconds{2};
    config.restart_stability_window = std::chrono::milliseconds{10};
    require(service.init(config), "FailService policy fixture must initialize");
    const auto started = service.start();
    require(static_cast<bool>(started), "FailService policy fixture must become Active");

    DNSTestPeer::stop_worker_unexpectedly(service, 0);
    const auto exit = wait_for_fatal(service, DNSFatalCode::UnexpectedWorkerStop, DNSControlRole::Worker,
                                     "an unsolicited RequestedStop must be normalized into a worker fatal");
    require(exit.fatal_error->worker_id == 0 && exit.fatal_error->instance_id == 1,
            "the worker fatal must identify the exact logical worker instance");
    require(service.health().restart_count == 0, "FailService must not launch a replacement worker");
}

} // namespace

int main()
{
    const auto socket_capability = dns::test::probe_ipv4_loopback_datagram_io();
    if (!socket_capability.available)
        return dns::test::socket_test_unavailable_exit(socket_capability, "lifecycle tests");

    const auto run = [](std::string_view name, auto test)
    {
        std::cerr << "running lifecycle case: " << name << '\n';
        test();
    };

    run("UniqueFd ownership", test_unique_fd_ownership);
    run("init retry and terminal Initialized stop", test_init_retry_second_init_and_initialized_stop);
    run("typed worker create failure", test_typed_worker_create_failure_after_partial_creation);
    run("all worker create steps remain typed", test_all_worker_create_steps_remain_typed);
    run("typed worker runtime-init failure", test_typed_worker_runtime_init_failure);
    run("typed worker thread failure", test_typed_worker_thread_failure_after_partial_start);
    run("typed control-role startup failures", test_typed_control_role_start_failures);
    run("multi-worker port snapshot and concurrent join", test_multiworker_port_snapshot_updates_and_concurrent_join);
    run("concurrent start accepts one attempt", test_concurrent_start_accepts_exactly_one_attempt);
    run("Starting can be cancelled and joined", test_starting_can_be_cancelled_and_joined);
    run("pre-commit completion and stale instance", test_supervisor_rejects_precommit_completion_and_stale_instance);
    run("DNS pre-commit worker failure rollback", test_dns_rolls_back_exact_precommit_worker_failure);
    run("TeardownIncomplete retains owners", test_teardown_incomplete_retains_owners_and_can_retry);
    run("runtime updates disabled", test_runtime_updates_disabled_do_not_start_coordinator);
    run("coordinator runtime fatal", test_coordinator_runtime_fatal);
    run("reclaimer runtime fatal", test_reclaimer_runtime_fatal);
    run("supervisor runtime fatal", test_supervisor_runtime_fatal);
    run("committed update survives A/B/C failures", test_committed_update_survives_control_role_failures);
    run("explicit stop and runtime fatal are first-wins", test_explicit_stop_and_runtime_fatal_are_first_wins);
    run("FailService policy reports exact worker failure", test_fail_service_policy_preserves_worker_failure);
    std::cout << "all lifecycle tests passed\n";
    return EXIT_SUCCESS;
}
