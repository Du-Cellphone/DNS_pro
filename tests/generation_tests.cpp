#include "FilterPublication.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <semaphore>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace dns::server
{

struct FilterPublicationTestPeer final
{
    static std::vector<std::pair<size_t, uint64_t>> retired_cohort(const FilterPublicationState &state)
    {
        std::scoped_lock                         lock{state.retirement_mutex_};
        std::vector<std::pair<size_t, uint64_t>> result;
        for (const auto &member : state.retired_.cohort)
            result.emplace_back(member.worker_id, member.instance_id);
        return result;
    }

    static bool retired_complete(const FilterPublicationState &state)
    {
        std::scoped_lock lock{state.retirement_mutex_};
        return state.retired_.pending && state.cohort_complete(state.retired_);
    }

    static bool terminal_complete(const FilterPublicationState &state)
    {
        std::scoped_lock lock{state.retirement_mutex_};
        return state.terminal_.pending && state.cohort_complete(state.terminal_);
    }

    static bool reclaimer_has_incomplete_record(const FilterPublicationState &state)
    {
        std::scoped_lock lock{state.retirement_mutex_};
        return state.reclaimer_active_ && state.retired_.pending && !state.cohort_complete(state.retired_);
    }

    static bool acquire_retirement_credit_observed(FilterPublicationState &state, std::stop_token stop_token, std::binary_semaphore &waiting) noexcept
    {
        try
        {
            std::unique_lock lock{state.retirement_mutex_};
            bool             announced_wait{false};
            const bool       ready = state.retirement_changed_.wait(
                lock, stop_token,
                [&]
                {
                    if (!announced_wait && state.retirement_credit_held_ && !state.publication_sealed_.load(std::memory_order_acquire))
                    {
                        announced_wait = true;
                        waiting.release();
                    }
                    return !state.retirement_credit_held_ || state.publication_sealed_.load(std::memory_order_acquire);
                });
            if (!ready || state.publication_sealed_.load(std::memory_order_acquire) || stop_token.stop_requested())
                return false;
            state.retirement_credit_held_ = true;
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    static bool synchronize_with_blocked_credit_waiter(const FilterPublicationState &state)
    {
        // The observed waiter announces while holding retirement_mutex_. If
        // this lock succeeds while the credit remains held, that waiter has
        // reached wait() and atomically released the mutex; it is not merely
        // a thread that has been created but has not yet been scheduled.
        std::scoped_lock lock{state.retirement_mutex_};
        return state.retirement_credit_held_ && state.retired_.pending;
    }

    static void publish_spurious_progress(FilterPublicationState &state) { state.publish_progress(); }
};

} // namespace dns::server

namespace
{

using namespace std::chrono_literals;
using dns::server::FilterGeneration;
using dns::server::FilterPublicationState;
using dns::server::FilterPublicationTestPeer;
using dns::server::FilterSnapshot;
using dns::server::SnapshotReclaimerReadyCode;
using dns::server::SnapshotReclaimerReadyResult;
using dns::server::SnapshotReclaimerResult;
using dns::server::WorkerEpoch;
using dns::server::WorkerRegistrationState;

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "generation test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

FilterSnapshot make_snapshot(std::vector<std::string> rules, FilterGeneration generation)
{
    auto snapshot = dns::server::build_filter_snapshot(rules, generation);
    require(snapshot.has_value(), "fixture snapshot must build");
    return std::move(*snapshot);
}

struct DeletionProbe final
{
    void record()
    {
        std::scoped_lock lock{mutex};
        threads.push_back(std::this_thread::get_id());
    }

    [[nodiscard]] size_t count() const
    {
        std::scoped_lock lock{mutex};
        return threads.size();
    }

    [[nodiscard]] std::thread::id only_thread() const
    {
        std::scoped_lock lock{mutex};
        return threads.size() == 1 ? threads.front() : std::thread::id{};
    }

    mutable std::mutex           mutex;
    std::vector<std::thread::id> threads;
};

struct ReclaimerReadyProbe final : dns::server::SnapshotReclaimerObserver
{
    void report_reclaimer_ready(SnapshotReclaimerReadyResult result) noexcept override
    {
        code.store(result.code, std::memory_order_relaxed);
        ready.release();
    }

    std::atomic<SnapshotReclaimerReadyCode> code{SnapshotReclaimerReadyCode::AlreadyRunning};
    std::binary_semaphore                   ready{0};
};

FilterSnapshot make_tracked_snapshot(std::vector<std::string> rules, FilterGeneration generation, DeletionProbe &probe)
{
    auto built = Filter::DomainBlocklist::build(rules);
    require(built.has_value(), "tracked fixture blocklist must build");
    auto *context = new dns::server::FilterContext{generation, std::move(*built)};
    return FilterSnapshot{context, [&probe](const dns::server::FilterContext *value)
                          {
                              probe.record();
                              delete value;
                          }};
}

FilterSnapshot take_registration_snapshot(std::optional<dns::server::FilterWorkerRegistration> &registration)
{
    require(registration.has_value(), "worker registration must succeed");
    FilterSnapshot snapshot = std::move(registration->snapshot);
    registration.reset();
    return snapshot;
}

void stop_reclaimer(FilterPublicationState &state, std::jthread &reclaimer)
{
    state.request_reclaimer_shutdown();
    if (reclaimer.joinable())
        reclaimer.join();
}

void test_full_cohort_and_b_thread_destruction()
{
    DeletionProbe          retired_probe;
    DeletionProbe          terminal_probe;
    FilterPublicationState state{make_tracked_snapshot({"old.example"}, 1, retired_probe),
                                 FilterPublicationState::Config{.maximum_workers = 2, .grace_timeout = 2s}};
    WorkerEpoch            epoch0;
    WorkerEpoch            epoch1;
    auto                   registration0 = state.register_worker(0, 1, epoch0);
    auto                   registration1 = state.register_worker(1, 1, epoch1);
    auto                   local0        = take_registration_snapshot(registration0);
    auto                   local1        = take_registration_snapshot(registration1);
    require(state.refresh_worker_snapshot(local0, 1, epoch0) && state.refresh_worker_snapshot(local1, 1, epoch1),
            "both workers must publish their initial generation");
    require(state.mark_worker_registered(0, 1, epoch0) && state.mark_worker_registered(1, 1, epoch1), "both exact tokens must become registered");

    std::binary_semaphore b_started{0};
    std::thread::id       b_thread_id;
    std::jthread          reclaimer{[&](std::stop_token token)
                           {
                               b_thread_id = std::this_thread::get_id();
                               b_started.release();
                               static_cast<void>(state.run_reclaimer(token));
                           }};
    b_started.acquire();

    require(state.acquire_retirement_credit({}), "the only retirement credit must be available");
    auto committed = state.commit(make_tracked_snapshot({"new.example"}, 2, terminal_probe));
    require(committed && committed->generation == 2, "generation two must commit");
    require(FilterPublicationTestPeer::retired_cohort(state) == std::vector<std::pair<size_t, uint64_t>>{{0, 1}, {1, 1}},
            "commit must capture the exact two-member cohort");

    std::binary_semaphore credit_waiting{0};
    std::promise<bool>    second_credit_result;
    auto                  second_credit = second_credit_result.get_future();
    std::jthread          credit_waiter{[&](std::stop_token token) {
        second_credit_result.set_value(FilterPublicationTestPeer::acquire_retirement_credit_observed(state, token, credit_waiting));
    }};
    credit_waiting.acquire();
    require(FilterPublicationTestPeer::synchronize_with_blocked_credit_waiter(state),
            "the second credit waiter must reach wait() and release retirement_mutex_ while the first credit is held");
    require(second_credit.wait_for(0ms) == std::future_status::timeout,
            "the next publication must not acquire credit or start a heavy build while one generation is unreclaimed");

    require(state.refresh_worker_snapshot(local0, 1, epoch0), "the first worker must switch at a safe point");
    require(!FilterPublicationTestPeer::retired_complete(state) && retired_probe.count() == 0,
            "one ack must neither complete the cohort nor destroy the old tree");

    require(state.refresh_worker_snapshot(local1, 1, epoch1), "the second worker must switch at a safe point");
    state.wait_until_reclaimed(2);
    require(retired_probe.count() == 1 && retired_probe.only_thread() == b_thread_id, "the sole old owner must be destroyed exactly once on B");
    require(second_credit.get(), "B reclaim must return the one normal retirement credit");
    state.release_uncommitted_credit();
    credit_waiter.join();
    const auto stats = state.retirement_stats();
    require(stats.unreclaimed_generations == 0 && stats.retired_bytes == 0 && !stats.retirement_credit_held,
            "B must return the credit and accounted bytes after reclaim");

    local0.reset();
    local1.reset();
    state.quiesce_worker(0, 1, epoch0);
    state.quiesce_worker(1, 1, epoch1);
    state.seal_publication();
    require(state.detach_terminal_snapshot(), "terminal owner must detach after workers quiesce");
    require(terminal_probe.count() == 0, "detaching the terminal owner must not destroy it on the coordinator");
    stop_reclaimer(state, reclaimer);
    require(terminal_probe.count() == 1 && terminal_probe.only_thread() == b_thread_id,
            "the active terminal owner must also be destroyed exactly once on B");
}

void test_spurious_progress_while_b_waits()
{
    DeletionProbe          retired_probe;
    FilterPublicationState state{make_tracked_snapshot({"old.example"}, 1, retired_probe),
                                 FilterPublicationState::Config{.maximum_workers = 1, .grace_timeout = 2s}};
    WorkerEpoch            epoch;
    auto                   registration = state.register_worker(0, 9, epoch);
    auto                   local        = take_registration_snapshot(registration);
    require(state.refresh_worker_snapshot(local, 9, epoch) && state.mark_worker_registered(0, 9, epoch),
            "spurious-progress fixture worker must own generation one");
    require(state.acquire_retirement_credit({}), "spurious-progress fixture must reserve the retirement record");
    require(state.commit(make_snapshot({"new.example"}, 2)).has_value(), "spurious-progress fixture generation must commit");

    ReclaimerReadyProbe                   ready_probe;
    std::promise<SnapshotReclaimerResult> result_promise;
    auto                                  result = result_promise.get_future();
    std::jthread reclaimer{[&](std::stop_token token) { result_promise.set_value(state.run_reclaimer(token, &ready_probe)); }};
    ready_probe.ready.acquire();
    require(ready_probe.code.load(std::memory_order_relaxed) == SnapshotReclaimerReadyCode::Ready, "B must report Ready before the wait is observed");
    require(result.wait_for(10ms) == std::future_status::timeout && FilterPublicationTestPeer::reclaimer_has_incomplete_record(state),
            "B must be live at the incomplete-cohort wait before spurious progress is sent");

    FilterPublicationTestPeer::publish_spurious_progress(state);
    require(result.wait_for(10ms) == std::future_status::timeout && FilterPublicationTestPeer::reclaimer_has_incomplete_record(state) &&
                retired_probe.count() == 0,
            "spurious progress must only re-evaluate the predicate, never reclaim an incomplete cohort");

    require(state.refresh_worker_snapshot(local, 9, epoch), "the exact worker ack must complete the normal grace period");
    state.wait_until_reclaimed(2);
    local.reset();
    state.quiesce_worker(0, 9, epoch);
    state.seal_publication();
    require(state.detach_terminal_snapshot(), "spurious-progress fixture terminal owner must detach");
    stop_reclaimer(state, reclaimer);
    require(result.get().code == dns::server::SnapshotReclaimerExitCode::RequestedStop,
            "B must stop normally after the exact ack and terminal reclaim");
}

void test_registration_linearization_lost_wake_and_spurious_progress()
{
    FilterPublicationState state{make_snapshot({"old.example"}, 1), FilterPublicationState::Config{.maximum_workers = 2, .grace_timeout = 2s}};
    WorkerEpoch            epoch0;
    WorkerEpoch            epoch1;

    auto registration0 = state.register_worker(0, 7, epoch0); // Starting before commit.
    require(registration0 && registration0->generation == 1, "the pre-commit participant must capture generation one");
    require(state.acquire_retirement_credit({}), "publication must reserve its record before commit");
    auto committed = state.commit(make_snapshot({"new.example"}, 2));
    require(committed.has_value(), "generation two must commit with a Starting participant");
    require(FilterPublicationTestPeer::retired_cohort(state) == std::vector<std::pair<size_t, uint64_t>>{{0, 7}},
            "a Starting participant that may own the old tree must enter the fixed cohort");

    auto registration1 = state.register_worker(1, 11, epoch1); // Registered after commit.
    require(registration1 && registration1->generation == 2, "a post-commit participant must start directly from the latest generation");
    require(FilterPublicationTestPeer::retired_cohort(state) == std::vector<std::pair<size_t, uint64_t>>{{0, 7}},
            "a post-commit instance must not be appended to the old fixed cohort");

    FilterPublicationTestPeer::publish_spurious_progress(state);
    require(!FilterPublicationTestPeer::retired_complete(state), "a notification without an exact ack must not complete grace period");

    auto local0 = take_registration_snapshot(registration0);
    auto local1 = take_registration_snapshot(registration1);
    require(state.refresh_worker_snapshot(local0, 7, epoch0), "the Starting worker must switch to generation two");
    require(state.refresh_worker_snapshot(local1, 11, epoch1), "the new worker must publish its initial generation");
    require(state.mark_worker_registered(0, 7, epoch0) && state.mark_worker_registered(1, 11, epoch1),
            "Ready revalidation must accept only workers on the current generation");

    // Both progress notifications happened before B starts. Predicate-first
    // scanning must still reclaim without relying on a future notification.
    std::jthread reclaimer{[&](std::stop_token token) { static_cast<void>(state.run_reclaimer(token)); }};
    state.wait_until_reclaimed(2);

    local0.reset();
    local1.reset();
    state.quiesce_worker(0, 7, epoch0);
    state.quiesce_worker(1, 11, epoch1);
    state.seal_publication();
    require(state.detach_terminal_snapshot(), "terminal snapshot must detach for cleanup");
    stop_reclaimer(state, reclaimer);
}

void test_exact_instance_ack_quiescence_and_terminal_rule()
{
    FilterPublicationState state{make_snapshot({"old.example"}, 1), FilterPublicationState::Config{.maximum_workers = 1, .grace_timeout = 2s}};
    WorkerEpoch            epoch;
    auto                   registration = state.register_worker(0, 1, epoch);
    auto                   local        = take_registration_snapshot(registration);
    require(state.refresh_worker_snapshot(local, 1, epoch) && state.mark_worker_registered(0, 1, epoch),
            "instance one must install the initial snapshot");

    require(state.acquire_retirement_credit({}), "normal retirement credit must be available");
    require(state.commit(make_snapshot({"new.example"}, 2)).has_value(), "generation two must commit");

    epoch.registration_state.store(WorkerRegistrationState::Unregistered, std::memory_order_release);
    require(!FilterPublicationTestPeer::retired_complete(state),
            "Exited/Unregistered without join and owner release must not prove grace completion");
    epoch.published_instance_id.store(2, std::memory_order_release);
    epoch.observed_generation.store(2, std::memory_order_release);
    require(!FilterPublicationTestPeer::retired_complete(state), "a new instance's high generation must not be attributed to the old exact token");

    epoch.published_instance_id.store(1, std::memory_order_release);
    local.reset();
    state.quiesce_worker(0, 1, epoch);
    std::jthread reclaimer{[&](std::stop_token token) { static_cast<void>(state.run_reclaimer(token)); }};
    state.wait_until_reclaimed(2);

    auto registration2 = state.register_worker(0, 2, epoch);
    auto local2        = take_registration_snapshot(registration2);
    require(state.refresh_worker_snapshot(local2, 2, epoch) && state.mark_worker_registered(0, 2, epoch),
            "replacement instance must install the latest active snapshot");
    state.seal_publication();
    require(state.detach_terminal_snapshot(), "terminal owner must detach independently of the normal credit");
    require(!FilterPublicationTestPeer::terminal_complete(state),
            "observing the current generation does not release the worker's current local owner");

    local2.reset();
    state.quiesce_worker(0, 2, epoch);
    require(FilterPublicationTestPeer::terminal_complete(state), "join/reset quiescence must prove that the terminal local owner was released");
    stop_reclaimer(state, reclaimer);
}

void test_grace_stall_keeps_owner_and_reports_exact_token()
{
    constexpr auto         grace_timeout = 20ms;
    DeletionProbe          probe;
    FilterPublicationState state{make_tracked_snapshot({"stalled.example"}, 1, probe),
                                 FilterPublicationState::Config{.maximum_workers = 1, .grace_timeout = grace_timeout}};
    WorkerEpoch            epoch;
    auto                   registration = state.register_worker(0, 42, epoch);
    auto                   local        = take_registration_snapshot(registration);
    require(state.refresh_worker_snapshot(local, 42, epoch) && state.mark_worker_registered(0, 42, epoch),
            "stall fixture worker must own generation one");
    require(state.acquire_retirement_credit({}), "stall fixture must reserve the retirement record");
    require(state.commit(make_snapshot({"replacement.example"}, 2)).has_value(), "stall fixture generation must commit");

    SnapshotReclaimerResult result;
    std::jthread            reclaimer{[&](std::stop_token token) { result = state.run_reclaimer(token); }};
    reclaimer.join();
    require(result.code == dns::server::SnapshotReclaimerExitCode::GracePeriodStalled && result.diagnostic,
            "a grace timeout must be diagnostic fatal, never force reclaim");
    require(result.diagnostic->target_generation == 2 && result.diagnostic->pending == std::vector<dns::server::PendingFilterParticipant>{{0, 42, 1}},
            "stall diagnostics must name the exact pending token and observed generation");
    require(result.diagnostic->retired_bytes > 0, "stall diagnostics must report the retained snapshot's non-zero accounted bytes");
    require(result.diagnostic->waited >= grace_timeout, "stall diagnostics must not report a timeout before the configured grace interval elapsed");
    require(probe.count() == 0 && state.retirement_stats().unreclaimed_generations == 1, "B failure must leave the stable retired owner intact");

    local.reset();
    state.quiesce_worker(0, 42, epoch);
    state.seal_publication();
    require(state.emergency_reclaim_converged() && probe.count() == 1, "only a post-join emergency successor may reclaim after B has exited");
    require(state.detach_terminal_snapshot() && state.emergency_reclaim_converged(),
            "emergency teardown must also drain the independent terminal owner");
}

} // namespace

int main()
{
    test_full_cohort_and_b_thread_destruction();
    test_spurious_progress_while_b_waits();
    test_registration_linearization_lost_wake_and_spurious_progress();
    test_exact_instance_ack_quiescence_and_terminal_rule();
    test_grace_stall_keeps_owner_and_reports_exact_token();
    std::cout << "all generation tests passed\n";
    return EXIT_SUCCESS;
}
