#include "DNS.h"
#include "WorkerSupervisor.h"
#include "protocol/DnsParser.h"
#include "protocol/DnsWriter.h"
#include "runtime/UniqueFd.h"
#include "tests/SocketTestSupport.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <semaphore>
#include <string_view>
#include <sys/socket.h>
#include <thread>

namespace dns::server
{

struct WorkerSupervisorTestPeer
{
    struct Snapshot
    {
        WorkerRecordState                     state;
        uint64_t                              instance;
        uint64_t                              quiesced;
        FilterGeneration                      observed;
        size_t                                attempts;
        bool                                  episode;
        bool                                  completed;
        std::chrono::steady_clock::time_point stable_at;
        std::chrono::steady_clock::time_point completed_at;
    };

    static Snapshot snapshot(WorkerSupervisor &supervisor, size_t worker_id = 0)
    {
        std::scoped_lock lock{supervisor.mutex_};
        const auto      &record = *supervisor.records_.at(worker_id);
        return {record.state_,
                record.instance_id_,
                record.epoch_.quiesced_through_instance_id.load(),
                record.epoch_.observed_generation.load(),
                record.recovery_attempts_,
                record.recovery_episode_,
                record.completion_.published,
                record.stable_at_,
                record.completion_.completed_at};
    }

    static void hooks(WorkerSupervisor &supervisor, WorkerSupervisorFaultHooks hooks)
    {
        std::scoped_lock lock{supervisor.mutex_};
        supervisor.config_.fault_hooks = hooks;
    }

    static void stop_at_activation(WorkerSupervisor &supervisor, size_t worker_id)
    {
        // Called by C, or while a probe explicitly parks C. The instance
        // cannot move until the caller releases that barrier.
        supervisor.records_[worker_id]->current_instance_->request_stop();
        std::unique_lock lock{supervisor.mutex_};
        supervisor.wakeup_.wait(lock, [&] { return supervisor.records_[worker_id]->completion_.published; });
    }

    static void stale_events(WorkerSupervisor &supervisor, size_t worker_id, uint64_t old_instance)
    {
        auto &record = *supervisor.records_[worker_id];
        supervisor.report_worker_ready(record, old_instance, WorkerReadyResult{WorkerReadyOutcome::InitError, std::nullopt});
        supervisor.report_worker_activated(record, old_instance);
        supervisor.report_worker_completion(record, old_instance,
                                            WorkerRunResult{WorkerRunOutcome::FatalExit, WorkerRuntimeError{WorkerRuntimeStep::Shutdown, EIO}});
        supervisor.config_.filter_publication->quiesce_worker(worker_id, old_instance, record.epoch_);
    }

    static void fail_join_once(WorkerSupervisor &supervisor, size_t worker_id)
    {
        std::scoped_lock lock{supervisor.mutex_};
        supervisor.join_failure_worker_once_ = worker_id;
    }
};

} // namespace dns::server

struct DNSTestPeer
{
    static dns::server::WorkerSupervisor &supervisor(DNS &service) { return *service.supervisor_; }
    static void                           fail_startup(DNS &service) { service.inject_worker_runtime_init_failure_for_test(0); }
    static void                           fail_reclaimer(DNS &service) { service.inject_reclaimer_runtime_failure_for_test(); }
};

namespace
{

using namespace std::chrono_literals;
using dns::server::WorkerRecordState;
using dns::server::WorkerRecoveryTestPoint;
using Peer = dns::server::WorkerSupervisorTestPeer;

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "recovery test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

template <typename Predicate>
void await(Predicate predicate, std::string_view message)
{
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!predicate())
    {
        require(std::chrono::steady_clock::now() < deadline, message);
        std::this_thread::sleep_for(1ms);
    }
}

DNSConfig config(size_t workers = 1, bool updates = true)
{
    DNSConfig result;
    result.worker_count             = workers;
    result.port                     = 0;
    result.cache_capacity           = 16;
    result.blocked_domains          = {"blocked.example"};
    result.runtime_updates_enabled  = updates;
    result.worker_failure_policy    = WorkerFailurePolicy::Restart;
    result.restart_initial_backoff  = 5ms;
    result.restart_max_backoff      = 20ms;
    result.restart_stability_window = 30s;
    return result;
}

uint16_t start(DNS &service, const DNSConfig &configuration)
{
    require(service.init(configuration), "recovery fixture must initialize");
    auto result = service.start();
    require(result.has_value(), "initial startup must become Active");
    return result->effective_bound_port;
}

void crash(dns::server::WorkerSupervisor &supervisor, size_t worker = 0)
{
    require(supervisor.inject_worker_unexpected_stop_for_testing(worker), "exact current instance must accept runtime fault");
}

void await_healthy(DNS &service, uint64_t successes)
{
    await(
        [&]
        {
            auto health = service.health();
            return health.state == DNSHealthState::Healthy && health.restart_success_count == successes;
        },
        "replacement must activate and restore Healthy");
    require(service.is_running(), "recovery must preserve lifecycle Active");
}

struct Pause
{
    WorkerRecoveryTestPoint point;
    std::atomic<bool>       armed{true};
    std::binary_semaphore   reached{0};
    std::binary_semaphore   released{0};

    explicit Pause(WorkerRecoveryTestPoint selected)
        : point(selected)
    {
    }

    static void probe(void *context, size_t, uint64_t, WorkerRecoveryTestPoint point) noexcept
    {
        auto &pause = *static_cast<Pause *>(context);
        if (point == pause.point && pause.armed.exchange(false))
        {
            pause.reached.release();
            pause.released.acquire();
        }
    }

    void install(dns::server::WorkerSupervisor &supervisor)
    {
        dns::server::WorkerSupervisorFaultHooks hooks;
        hooks.recovery_probe_context = this;
        hooks.recovery_probe         = probe;
        Peer::hooks(supervisor, hooks);
    }

    void wait() { require(reached.try_acquire_for(5s), "C must reach the selected recovery boundary"); }
};

void query_blocked(uint16_t port, std::string_view domain)
{
    dns::runtime::UniqueFd socket{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(socket), "UDP client must open");
    timeval timeout{2, 0};
    require(::setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "client timeout must apply");
    auto name = dns::protocol::DomainName::from_text(domain);
    require(name.has_value(), "query name must parse");
    dns::protocol::Header header;
    header.id = 0x1414;
    const std::array questions{dns::protocol::Question{std::move(*name), 1, 1}};
    auto             packet = dns::protocol::serialize_query(header, questions);
    require(packet.has_value(), "query must serialize");
    sockaddr_in address{};
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port        = htons(port);
    require(::sendto(socket.get(), packet->data(), packet->size(), 0, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) ==
                static_cast<ssize_t>(packet->size()),
            "UDP query must send");
    std::array<std::byte, 512> buffer{};
    const auto                 size = ::recv(socket.get(), buffer.data(), buffer.size(), 0);
    require(size > 0, "a Running worker must still answer on the frozen port");
    auto response = dns::protocol::parse_message(std::span{buffer}.first(static_cast<size_t>(size)));
    require(response && response->header.id == header.id &&
                response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::Refused),
            "replacement must filter using the current generation");
}

void test_degraded_recovery_and_generation()
{
    DNS  service;
    auto configuration                    = config(2);
    configuration.restart_initial_backoff = 400ms;
    configuration.restart_max_backoff     = 400ms;
    const auto port                       = start(service, configuration);
    auto      &supervisor                 = DNSTestPeer::supervisor(service);
    crash(supervisor);
    await([&] { return Peer::snapshot(supervisor).state == WorkerRecordState::Backoff; }, "old worker must join before backoff");
    auto health = service.health();
    require(service.is_running() && health.state == DNSHealthState::Degraded && health.available_workers == 1 && health.desired_workers == 2,
            "one of two workers failing must preserve Active/Degraded");
    require(health.last_error && health.last_error->instance_id == 1 && health.last_error->code == DNSFatalCode::UnexpectedWorkerStop,
            "recoverable unexpected stop must retain the exact diagnostic");
    require(Peer::snapshot(supervisor).quiesced == 1, "old instance must release its snapshot before cache reuse");
    query_blocked(port, "blocked.example");
    auto version = service.replace_blocked_domains({"new.example"});
    require(version.has_value(), "publication must remain responsive during recovery backoff");
    await_healthy(service, 1);
    const auto replacement = Peer::snapshot(supervisor);
    require(replacement.instance == 2 && replacement.observed == version->generation && replacement.attempts == 1 && service.bound_port() == port,
            "new instance must install current generation and reuse the service port");
    query_blocked(port, "new.example");
    Peer::stale_events(supervisor, 0, 1);
    const auto after_stale = Peer::snapshot(supervisor);
    require(after_stale.instance == 2 && after_stale.state == WorkerRecordState::Running && !after_stale.completed && after_stale.quiesced == 1,
            "old ready/completion/quiescence tokens must not change the replacement");
    require(service.join().code == DNSServiceExitCode::ExplicitStop, "recovered service must stop normally");
    require(service.health().restart_count == 1 && service.health().restart_success_count == 1 && service.health().restart_failure_count == 0,
            "lifetime counters must distinguish attempts, activation and failures");
}

void test_single_worker_unavailable_then_healthy()
{
    Pause      pause{WorkerRecoveryTestPoint::BeforeCreate};
    DNS        service;
    const auto port       = start(service, config(1, false));
    auto      &supervisor = DNSTestPeer::supervisor(service);
    pause.install(supervisor);
    crash(supervisor);
    pause.wait();
    require(service.is_running() && service.health().state == DNSHealthState::Unavailable && service.health().available_workers == 0 &&
                service.bound_port() == port,
            "zero Running workers during a recovery episode is Active/Unavailable, retaining the port");
    pause.released.release();
    await_healthy(service, 1);
    query_blocked(port, "blocked.example");
    require(service.join().code == DNSServiceExitCode::ExplicitStop, "static-snapshot recovery must shut down");
}

void test_replacement_failure_budget()
{
    for (int kind = 0; kind != 3; ++kind)
    {
        DNS  service;
        auto configuration                 = config();
        configuration.restart_max_attempts = 2;
        start(service, configuration);
        auto                                   &supervisor = DNSTestPeer::supervisor(service);
        dns::server::WorkerSupervisorFaultHooks hooks;
        hooks.failure_from_instance = 2;
        if (kind == 0)
        {
            hooks.create_failure_worker = 0;
            hooks.create_failure_step   = dns::server::WorkerInitStep::BindSocket;
            hooks.create_failure_error  = EADDRINUSE;
        }
        else if (kind == 1)
            hooks.thread_failure_worker = 0;
        else
            hooks.runtime_init_failure_worker = 0;
        Peer::hooks(supervisor, hooks);
        crash(supervisor);
        const auto exit = service.wait();
        require(exit.code == DNSServiceExitCode::Fatal && exit.fatal_error && exit.fatal_error->code == DNSFatalCode::RestartBudgetExhausted &&
                    exit.fatal_error->instance_id == 3,
                "two failed replacements must exhaust the same runtime episode");
        const auto health = service.health();
        require(health.restart_count == 2 && health.restart_failure_count == 2 && health.restart_success_count == 0 &&
                    service.lifecycle_state() == DNSLifecycleState::Failed,
                "failed create/thread/Ready attempts must consume the budget");
        if (kind == 0)
            require(exit.fatal_error->worker_create_error && exit.fatal_error->error_number == EADDRINUSE,
                    "budget exhaustion must preserve the bind error");
        if (kind == 2)
            require(exit.fatal_error->worker_error && exit.fatal_error->worker_error->step == dns::server::WorkerRuntimeStep::StartScheduler,
                    "replacement InitError must remain a runtime recovery failure");
    }
}

void test_short_lived_workers_do_not_reset_budget()
{
    DNS  service;
    auto configuration                 = config();
    configuration.restart_max_attempts = 2;
    start(service, configuration);
    auto &supervisor = DNSTestPeer::supervisor(service);
    for (uint64_t successes = 1; successes <= 2; ++successes)
    {
        crash(supervisor);
        await_healthy(service, successes);
    }
    crash(supervisor);
    const auto exit = service.wait();
    require(exit.code == DNSServiceExitCode::Fatal && exit.fatal_error && exit.fatal_error->code == DNSFatalCode::RestartBudgetExhausted,
            "brief Ready/Running periods must not reset the consecutive failure budget");
    require(service.health().restart_count == 2 && service.health().restart_failure_count == 2,
            "early exits of activated replacements still consume the existing budget");
}

void test_stability_resets_only_episode_budget()
{
    DNS  service;
    auto configuration                     = config();
    configuration.restart_max_attempts     = 1;
    configuration.restart_stability_window = 25ms;
    start(service, configuration);
    auto &supervisor = DNSTestPeer::supervisor(service);
    crash(supervisor);
    await_healthy(service, 1);
    await(
        [&]
        {
            auto state = Peer::snapshot(supervisor);
            return !state.episode && state.attempts == 0;
        },
        "continuous Running for the stability window must close the episode");
    crash(supervisor);
    await_healthy(service, 2);
    require(service.health().restart_count == 2, "stability must not erase lifetime recovery counters");
    require(service.join().code == DNSServiceExitCode::ExplicitStop, "stable repeated recovery must stop normally");
}

void test_replacement_exits_before_activation()
{
    DNS  service;
    auto configuration                 = config();
    configuration.restart_max_attempts = 2;
    start(service, configuration);
    auto                                   &supervisor = DNSTestPeer::supervisor(service);
    dns::server::WorkerSupervisorFaultHooks hooks;
    hooks.recovery_probe_context = &supervisor;
    hooks.recovery_probe         = [](void *context, size_t worker, uint64_t, WorkerRecoveryTestPoint point) noexcept
    {
        if (point == WorkerRecoveryTestPoint::Activated)
            Peer::stop_at_activation(*static_cast<dns::server::WorkerSupervisor *>(context), worker);
    };
    Peer::hooks(supervisor, hooks);
    crash(supervisor);
    auto exit = service.wait();
    require(exit.code == DNSServiceExitCode::Fatal && exit.fatal_error && exit.fatal_error->code == DNSFatalCode::RestartBudgetExhausted &&
                service.health().restart_count == 2 && service.health().restart_success_count == 0,
            "completion before C activates a replacement must consume budget without counting it Running");
}

void test_late_observation_does_not_award_stability()
{
    Pause pause{WorkerRecoveryTestPoint::Running};
    DNS   service;
    auto  configuration                    = config();
    configuration.restart_max_attempts     = 1;
    configuration.restart_stability_window = 200ms;
    start(service, configuration);
    auto &supervisor = DNSTestPeer::supervisor(service);
    pause.install(supervisor);
    crash(supervisor);
    pause.wait();
    Peer::stop_at_activation(supervisor, 0);
    const auto exited = Peer::snapshot(supervisor);
    require(exited.completed && exited.completed_at < exited.stable_at, "the replacement must exit before the stability deadline while C is parked");
    std::this_thread::sleep_until(exited.stable_at + 5ms);
    pause.released.release();
    const auto exit = service.wait();
    require(exit.code == DNSServiceExitCode::Fatal && exit.fatal_error && exit.fatal_error->code == DNSFatalCode::RestartBudgetExhausted &&
                service.health().restart_count == 1,
            "C observing a completion after the deadline must not award stability to an early exit");
}

void test_exponential_backoff_is_capped()
{
    struct Trace
    {
        std::array<std::chrono::steady_clock::time_point, 4> attempts{};
        size_t                                               count{0};
    } trace;
    DNS  service;
    auto configuration                    = config();
    configuration.restart_max_attempts    = 4;
    configuration.restart_initial_backoff = 15ms;
    configuration.restart_max_backoff     = 25ms;
    start(service, configuration);
    auto                                   &supervisor = DNSTestPeer::supervisor(service);
    dns::server::WorkerSupervisorFaultHooks hooks;
    hooks.failure_from_instance  = 2;
    hooks.create_failure_worker  = 0;
    hooks.recovery_probe_context = &trace;
    hooks.recovery_probe         = [](void *context, size_t, uint64_t, WorkerRecoveryTestPoint point) noexcept
    {
        if (point == WorkerRecoveryTestPoint::BeforeCreate)
        {
            auto &trace = *static_cast<Trace *>(context);
            if (trace.count < trace.attempts.size())
                trace.attempts[trace.count++] = std::chrono::steady_clock::now();
        }
    };
    Peer::hooks(supervisor, hooks);
    const auto before = std::chrono::steady_clock::now();
    crash(supervisor);
    require(service.wait().code == DNSServiceExitCode::Fatal && trace.count == 4, "all scheduled attempts must run before budget exhaustion");
    require(trace.attempts[0] - before >= 15ms, "first replacement must wait initial backoff");
    for (size_t i = 1; i < trace.attempts.size(); ++i)
        require(trace.attempts[i] - trace.attempts[i - 1] >= 25ms, "subsequent attempts must respect the capped doubled delay");
    // The long-backoff stop test separately covers saturated clock deadlines.
}

void test_updates_and_repeated_recovery_with_udp()
{
    DNS  service;
    auto configuration                 = config(2);
    configuration.restart_max_attempts = 20;
    const auto        port             = start(service, configuration);
    auto             &supervisor       = DNSTestPeer::supervisor(service);
    std::atomic<bool> updates_ok{true};
    std::jthread      updater{[&]
                         {
                             uint64_t previous = 1;
                             for (unsigned i = 0; i < 40; ++i)
                             {
                                 auto result = service.replace_blocked_domains({"blocked.example", i % 2 ? "odd.example" : "even.example"});
                                 if (!result || result->generation <= previous)
                                 {
                                     updates_ok.store(false);
                                     return;
                                 }
                                 previous = result->generation;
                                 std::this_thread::sleep_for(2ms);
                             }
                         }};
    for (uint64_t i = 0; i < 12; ++i)
    {
        crash(supervisor, i % 2);
        await_healthy(service, i + 1);
        query_blocked(port, "blocked.example");
    }
    updater.join();
    require(updates_ok.load() && service.filter_version()->generation == 41 && service.health().restart_count == 12,
            "concurrent publication and exact-instance recovery must keep generations monotonic and serve UDP");
    require(service.join().code == DNSServiceExitCode::ExplicitStop, "repeated recovery must leave no pending owners on shutdown");
}

void test_stop_at_recovery_boundaries()
{
    for (const auto point : {WorkerRecoveryTestPoint::BeforeCreate, WorkerRecoveryTestPoint::AfterCreate, WorkerRecoveryTestPoint::Ready,
                             WorkerRecoveryTestPoint::Activated})
    {
        Pause pause{point};
        DNS   service;
        start(service, config());
        auto &supervisor = DNSTestPeer::supervisor(service);
        pause.install(supervisor);
        crash(supervisor);
        pause.wait();
        service.request_stop();
        pause.released.release();
        const auto exit = service.join();
        require(exit.code == DNSServiceExitCode::ExplicitStop && !exit.fatal_error, "explicit stop must win each in-flight recovery boundary");
        require(service.health().restart_success_count == 0, "stop must prevent a candidate from entering Running");
        require(service.health().restart_count == (point == WorkerRecoveryTestPoint::BeforeCreate ? 0U : 1U),
                "stop before create must close restart admission without consuming another attempt");
    }
}

void test_stop_cancels_long_backoff()
{
    DNS  service;
    auto configuration                    = config();
    configuration.restart_initial_backoff = std::chrono::milliseconds::max();
    configuration.restart_max_backoff     = std::chrono::milliseconds::max();
    start(service, configuration);
    auto &supervisor = DNSTestPeer::supervisor(service);
    crash(supervisor);
    await([&] { return Peer::snapshot(supervisor).state == WorkerRecordState::Backoff; }, "worker must enter long backoff");
    const auto before = std::chrono::steady_clock::now();
    require(service.join().code == DNSServiceExitCode::ExplicitStop && std::chrono::steady_clock::now() - before < 1s,
            "stop must wake backoff immediately");
    require(service.health().restart_count == 0, "cancelled backoff must not launch a replacement");
}

void test_publication_while_replacement_waits_for_activation()
{
    Pause      pause{WorkerRecoveryTestPoint::Ready};
    DNS        service;
    const auto port       = start(service, config());
    auto      &supervisor = DNSTestPeer::supervisor(service);
    pause.install(supervisor);
    crash(supervisor);
    pause.wait();
    auto version = service.replace_blocked_domains({"during-ready.example"});
    require(version.has_value() && Peer::snapshot(supervisor).observed == version->generation,
            "Starting participant must refresh and satisfy the cohort while its activation is held");
    pause.released.release();
    await_healthy(service, 1);
    query_blocked(port, "during-ready.example");
    require(service.join().code == DNSServiceExitCode::ExplicitStop, "publication/recovery interleaving must drain");
}

void test_port_takeover_exhausts_budget()
{
    Pause pause{WorkerRecoveryTestPoint::BeforeCreate};
    DNS   service;
    auto  configuration                = config();
    configuration.restart_max_attempts = 2;
    const auto port                    = start(service, configuration);
    auto      &supervisor              = DNSTestPeer::supervisor(service);
    pause.install(supervisor);
    crash(supervisor);
    pause.wait();
    dns::runtime::UniqueFd occupant{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(occupant), "port occupant must create socket");
    sockaddr_in address{};
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port        = htons(port);
    require(::bind(occupant.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0,
            "the old listener must be closed before attempting replacement");
    pause.released.release();
    const auto exit = service.wait();
    require(exit.code == DNSServiceExitCode::Fatal && exit.fatal_error && exit.fatal_error->code == DNSFatalCode::RestartBudgetExhausted &&
                exit.fatal_error->worker_create_error && exit.fatal_error->worker_create_error->step == dns::server::WorkerInitStep::BindSocket &&
                exit.fatal_error->error_number == EADDRINUSE,
            "a stolen frozen port must exhaust the budget with the real bind error");
    require(service.bound_port() == port && service.health().restart_count == 2, "recovery must never silently bind a different ephemeral port");
}

void test_unjoined_instance_keeps_epoch()
{
    DNS service;
    start(service, config());
    auto &supervisor = DNSTestPeer::supervisor(service);
    Peer::fail_join_once(supervisor, 0);
    crash(supervisor);
    await([&] { return service.lifecycle_state() == DNSLifecycleState::Stopping; }, "join failure must request external fatal teardown");
    const auto record = Peer::snapshot(supervisor);
    require(record.instance == 1 && record.quiesced == 0 && service.health().restart_count == 0,
            "an unjoined worker must retain its epoch and must never be replaced");
    const auto exit = service.join();
    require(exit.code == DNSServiceExitCode::Fatal && exit.fatal_error && exit.fatal_error->code == DNSFatalCode::WorkerJoinFailed,
            "external successor may retry joining only after C has exited");
}

void test_startup_and_control_failure_never_restart()
{
    {
        DNS service;
        require(service.init(config()), "startup failure fixture must initialize");
        DNSTestPeer::fail_startup(service);
        const auto result = service.start();
        require(!result && result.error().code == DNSStartErrorCode::WorkerRuntimeInitFailed &&
                    service.lifecycle_state() == DNSLifecycleState::Failed && service.health().restart_count == 0,
                "Restart policy must not recover an initial startup failure");
    }
    {
        DNS  service;
        auto configuration                    = config();
        configuration.restart_initial_backoff = 1h;
        configuration.restart_max_backoff     = 1h;
        start(service, configuration);
        auto &supervisor = DNSTestPeer::supervisor(service);
        crash(supervisor);
        await([&] { return Peer::snapshot(supervisor).state == WorkerRecordState::Backoff; }, "fixture must await recovery");
        DNSTestPeer::fail_reclaimer(service);
        const auto exit = service.wait();
        require(exit.code == DNSServiceExitCode::Fatal && exit.fatal_error && exit.fatal_error->code == DNSFatalCode::ReclaimerExited &&
                    service.health().restart_count == 0,
                "global control failure must cancel recovery and preserve its own fatal cause");
    }
}

} // namespace

int main()
{
    const auto capability = dns::test::probe_ipv4_loopback_datagram_io();
    if (!capability.available)
        return dns::test::socket_test_unavailable_exit(capability, "recovery tests");
    const auto run = [](std::string_view name, auto test)
    {
        std::cout << name << std::endl;
        test();
    };
    run("Active/Degraded, generation, stale events and UDP", test_degraded_recovery_and_generation);
    run("Active/Unavailable with one worker", test_single_worker_unavailable_then_healthy);
    run("replacement create/thread/init budget", test_replacement_failure_budget);
    run("brief Running does not reset budget", test_short_lived_workers_do_not_reset_budget);
    run("stability window resets episode", test_stability_resets_only_episode_budget);
    run("replacement exits before activation", test_replacement_exits_before_activation);
    run("exponential backoff reaches its cap", test_exponential_backoff_is_capped);
    run("delayed C observation does not award stability", test_late_observation_does_not_award_stability);
    run("updates and repeated recovery with UDP", test_updates_and_repeated_recovery_with_udp);
    run("stop at every recovery boundary", test_stop_at_recovery_boundaries);
    run("stop cancels long backoff", test_stop_cancels_long_backoff);
    run("publication while replacement waits at Ready", test_publication_while_replacement_waits_for_activation);
    run("real port takeover exhausts budget", test_port_takeover_exhausts_budget);
    run("unjoined instance retains epoch", test_unjoined_instance_keeps_epoch);
    run("startup and control failures cannot restart", test_startup_and_control_failure_never_restart);
}
