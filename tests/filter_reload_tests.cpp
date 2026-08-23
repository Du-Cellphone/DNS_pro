#include "FilterUpdateController.h"

#include <algorithm>
#include <atomic>
#include <barrier>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <limits>
#include <optional>
#include <semaphore>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace dns::server
{

struct FilterUpdateControllerTestPeer final
{
    static void inject_postcommit_failure_for_testing(FilterUpdateController &controller) noexcept
    {
        controller.inject_postcommit_failure_for_testing();
    }
};

} // namespace dns::server

namespace
{

using namespace std::chrono_literals;
using dns::server::FilterGeneration;
using dns::server::FilterPublicationState;
using dns::server::FilterSnapshot;
using dns::server::FilterUpdateController;
using dns::server::FilterUpdateErrorCode;
using dns::server::FilterUpdateFuture;
using dns::server::FilterUpdateResult;
using dns::server::WorkerEpoch;

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "filter reload test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

template <typename Predicate>
bool eventually(Predicate &&predicate, std::chrono::milliseconds timeout = 2s)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do
    {
        if (predicate())
            return true;
        std::this_thread::yield();
    } while (std::chrono::steady_clock::now() < deadline);
    return predicate();
}

FilterSnapshot make_snapshot(std::vector<std::string> rules, FilterGeneration generation)
{
    auto snapshot = dns::server::build_filter_snapshot(rules, generation);
    require(snapshot.has_value(), "filter reload fixture snapshot must build");
    return std::move(*snapshot);
}

struct ControllerHarness final
{
    ControllerHarness(FilterSnapshot initial, FilterUpdateController::Builder builder = {}, dns::server::FilterUpdateLimits limits = {})
        : publication(std::move(initial), FilterPublicationState::Config{.maximum_workers = 0})
        , controller(publication, std::move(builder), limits)
        , reclaimer([this](std::stop_token token) { static_cast<void>(publication.run_reclaimer(token)); })
        , runner([this](std::stop_token token) { static_cast<void>(controller.run(token)); })
    {
    }

    ~ControllerHarness() { stop(); }

    void stop()
    {
        if (runner.joinable())
        {
            controller.request_terminal_detach();
            runner.join();
        }
        publication.request_reclaimer_shutdown();
        if (reclaimer.joinable())
            reclaimer.join();
    }

    FilterPublicationState publication;
    FilterUpdateController controller;
    std::jthread           reclaimer;
    std::jthread           runner;
};

struct RegisteredWorkerControllerHarness final
{
    RegisteredWorkerControllerHarness(FilterSnapshot initial, FilterUpdateController::Builder builder = {},
                                      dns::server::FilterUpdateLimits limits = {})
        : publication(std::move(initial), FilterPublicationState::Config{.maximum_workers = 1})
        , controller(publication, std::move(builder), limits)
    {
        auto registration = publication.register_worker(0, instance_id, epoch);
        require(registration.has_value(), "the participant fixture must register its worker");
        local_snapshot = std::move(registration->snapshot);
        require(publication.refresh_worker_snapshot(local_snapshot, instance_id, epoch),
                "the participant fixture must install its initial local snapshot");
        require(publication.mark_worker_registered(0, instance_id, epoch), "the participant fixture must finish worker registration");
        worker_registered = true;

        reclaimer = std::jthread{[this](std::stop_token token) { static_cast<void>(publication.run_reclaimer(token)); }};
        runner    = std::jthread{[this](std::stop_token token)
                              {
                                  const auto result = controller.run(token);
                                  runner_exit.store(result.code, std::memory_order_relaxed);
                                  runner_finished.store(true, std::memory_order_release);
                              }};
    }

    ~RegisteredWorkerControllerHarness() { stop(); }

    void acknowledge_current_generation()
    {
        require(publication.refresh_worker_snapshot(local_snapshot, instance_id, epoch),
                "the fixture worker must acknowledge the current generation");
    }

    void quiesce_worker()
    {
        if (!worker_registered)
            return;
        local_snapshot.reset();
        publication.quiesce_worker(0, instance_id, epoch);
        worker_registered = false;
    }

    void stop()
    {
        if (stopped)
            return;
        stopped = true;

        controller.request_terminal_detach();
        if (worker_registered)
            static_cast<void>(publication.refresh_worker_snapshot(local_snapshot, instance_id, epoch));
        quiesce_worker();
        if (runner.joinable())
            runner.join();

        require(publication.detach_terminal_snapshot(), "the fixture must detach the terminal snapshot");
        publication.request_reclaimer_shutdown();
        if (reclaimer.joinable())
            reclaimer.join();
    }

    static constexpr uint64_t instance_id = 1;

    FilterPublicationState                         publication;
    FilterUpdateController                         controller;
    WorkerEpoch                                    epoch;
    FilterSnapshot                                 local_snapshot;
    bool                                           worker_registered{false};
    bool                                           stopped{false};
    std::atomic<dns::server::FilterRunnerExitCode> runner_exit{dns::server::FilterRunnerExitCode::RequestedStop};
    std::atomic<bool>                              runner_finished{false};
    std::jthread                                   reclaimer;
    std::jthread                                   runner;
};

FilterUpdateResult await(FilterUpdateFuture future, std::string_view message)
{
    require(future.wait_for(2s) == std::future_status::ready, message);
    return future.get();
}

void require_error(const FilterUpdateResult &result, FilterUpdateErrorCode code, std::string_view message)
{
    require(!result && result.error().code == code, message);
}

void test_successful_reload_and_failed_reload_rollback()
{
    ControllerHarness harness{make_snapshot({"old.example"}, dns::server::kInitialFilterGeneration)};
    auto             &controller = harness.controller;

    const auto initial = controller.current_version();
    require(initial.generation == 1 && initial.rule_count == 1, "initial snapshot must be generation one");

    auto replaced = await(controller.submit_replace({"new.example", "second.example"}), "a valid reload must complete");
    require(replaced && replaced->generation == 2 && replaced->rule_count == 2, "a successful reload must publish generation two");

    require(harness.publication.current_version().generation == 2 && harness.publication.current_matches("child.new.example") &&
                harness.publication.current_matches("second.example") && !harness.publication.current_matches("old.example"),
            "the new generation must atomically replace the complete rule set");

    auto invalid = await(controller.submit_replace({"valid.example", "*.bad.example"}), "an invalid reload must complete with an error");
    require_error(invalid, FilterUpdateErrorCode::BuildFailed, "an invalid rule must report a build failure");
    require(invalid.error().build_error && invalid.error().build_error->code == Filter::BlocklistBuildErrorCode::WildcardNotSupported &&
                invalid.error().build_error->rule_index == 1,
            "a build failure must retain the exact rule error");
    require(harness.publication.current_version().generation == 2 && harness.publication.current_matches("new.example"),
            "a failed reload must retain the old published behavior and generation");

    auto after_failure = await(controller.submit_replace({"third.example"}), "a valid reload after failure must complete");
    require(after_failure && after_failure->generation == 3 && after_failure->rule_count == 1, "a failed build must not consume a generation");

    harness.stop();
}

void test_concurrent_reloads_are_serialized()
{
    ControllerHarness harness{make_snapshot({}, dns::server::kInitialFilterGeneration)};
    auto             &controller = harness.controller;

    std::barrier                      start_gate{3};
    std::optional<FilterUpdateResult> first_result;
    std::optional<FilterUpdateResult> second_result;

    std::jthread first{[&]
                       {
                           start_gate.arrive_and_wait();
                           first_result.emplace(await(controller.submit_replace({"first.concurrent"}), "first concurrent reload must complete"));
                       }};
    std::jthread second{[&]
                        {
                            start_gate.arrive_and_wait();
                            second_result.emplace(await(controller.submit_replace({"second.concurrent"}), "second concurrent reload must complete"));
                        }};
    start_gate.arrive_and_wait();
    first.join();
    second.join();

    require(first_result && *first_result && second_result && *second_result, "both concurrent reloads must succeed");
    const auto first_generation  = first_result->value().generation;
    const auto second_generation = second_result->value().generation;
    require(std::min(first_generation, second_generation) == 2 && std::max(first_generation, second_generation) == 3,
            "concurrent reloads must receive unique consecutive generations");

    const bool first_won = first_generation == 3;
    require(harness.publication.current_version().generation == 3 &&
                harness.publication.current_matches(first_won ? "first.concurrent" : "second.concurrent") &&
                !harness.publication.current_matches(first_won ? "second.concurrent" : "first.concurrent"),
            "the final snapshot must match the request that received the final generation");

    harness.stop();
}

void test_builder_execution_is_fifo_and_serial()
{
    std::binary_semaphore first_entered{0};
    std::binary_semaphore release_first{0};
    std::binary_semaphore second_entered{0};
    std::atomic<size_t>   calls{0};
    std::atomic<size_t>   active_builders{0};
    std::atomic<size_t>   maximum_active_builders{0};

    FilterUpdateController::Builder ordered_builder = [&](std::span<const std::string> rules, FilterGeneration generation, std::stop_token stop_token)
    {
        const size_t call_index = calls.fetch_add(1, std::memory_order_relaxed);
        const size_t active     = active_builders.fetch_add(1, std::memory_order_relaxed) + 1;
        size_t       maximum    = maximum_active_builders.load(std::memory_order_relaxed);
        while (maximum < active && !maximum_active_builders.compare_exchange_weak(maximum, active, std::memory_order_relaxed))
        {
        }

        if (call_index == 0)
        {
            first_entered.release();
            release_first.acquire();
        }
        else if (call_index == 1)
        {
            second_entered.release();
        }

        auto result = dns::server::build_filter_snapshot(rules, generation, stop_token);
        active_builders.fetch_sub(1, std::memory_order_relaxed);
        return result;
    };

    ControllerHarness harness{make_snapshot({}, dns::server::kInitialFilterGeneration), std::move(ordered_builder)};
    auto             &controller = harness.controller;

    auto first = controller.submit_replace({"first.fifo"});
    first_entered.acquire();
    auto second = controller.submit_replace({"second.fifo"});

    require(!second_entered.try_acquire(), "the second builder must not start while the first builder is blocked");
    release_first.release();

    auto first_result = await(std::move(first), "the first FIFO reload must complete");
    second_entered.acquire();
    auto second_result = await(std::move(second), "the second FIFO reload must complete");
    require(first_result && first_result->generation == 2 && second_result && second_result->generation == 3,
            "queued reloads must publish in submission order");
    require(calls.load(std::memory_order_relaxed) == 2 && maximum_active_builders.load(std::memory_order_relaxed) == 1,
            "the update controller must invoke at most one snapshot builder at a time");
    require(harness.publication.current_matches("second.fifo") && !harness.publication.current_matches("first.fifo"),
            "the final FIFO generation must contain only the second replacement rule set");

    harness.stop();
}

void test_close_during_build_cancels_inflight_and_queued_requests()
{
    std::binary_semaphore entered_build{0};
    std::binary_semaphore release_build{0};

    FilterUpdateController::Builder blocking_builder = [&](std::span<const std::string> rules, FilterGeneration generation, std::stop_token)
    {
        entered_build.release();
        release_build.acquire();
        return dns::server::build_filter_snapshot(rules, generation);
    };

    ControllerHarness harness{make_snapshot({"stable.example"}, dns::server::kInitialFilterGeneration), std::move(blocking_builder)};
    auto             &controller = harness.controller;

    auto inflight = controller.submit_replace({"inflight.example"});
    entered_build.acquire();

    std::vector<FilterUpdateFuture> queued;
    queued.reserve(FilterUpdateController::kMaximumPendingUpdates);
    for (size_t index = 0; index < FilterUpdateController::kMaximumPendingUpdates; ++index)
        queued.push_back(controller.submit_replace({"queued-" + std::to_string(index) + ".example"}));

    auto overflow = await(controller.submit_replace({"overflow.example"}), "a full update queue must reject excess work immediately");
    require_error(overflow, FilterUpdateErrorCode::QueueFull, "the update queue must have a fixed command-count limit");

    controller.close();
    release_build.release();

    auto inflight_result = await(std::move(inflight), "an in-flight reload must complete when the controller closes");
    for (auto &future : queued)
    {
        auto queued_result = await(std::move(future), "a queued reload must complete when the controller closes");
        require_error(queued_result, FilterUpdateErrorCode::ShuttingDown, "a queued reload must be cancelled by close");
    }
    require_error(inflight_result, FilterUpdateErrorCode::ShuttingDown, "an in-flight reload must be cancelled before publication");
    require(harness.publication.current_version().generation == 1, "closing during a build must not commit a new generation");
    harness.runner.join();

    auto rejected = await(controller.submit_replace({"late.example"}), "a reload submitted after close must be immediately ready");
    require_error(rejected, FilterUpdateErrorCode::ShuttingDown, "a closed controller must reject new work");
}

void test_terminal_stop_does_not_reclassify_a_committed_update()
{
    RegisteredWorkerControllerHarness harness{make_snapshot({"old.example"}, dns::server::kInitialFilterGeneration)};

    auto committed = harness.controller.submit_replace({"committed.example"});
    require(eventually([&] { return harness.publication.current_generation() == 2; }), "the update must reach the publication commit point");
    require(committed.wait_for(0s) != std::future_status::ready,
            "the committed update must remain pending while its exact cohort has not acknowledged it");

    harness.controller.request_terminal_detach();
    require(committed.wait_for(0s) != std::future_status::ready, "sealing A after commit must not complete the command as shutting down");
    harness.acknowledge_current_generation();

    auto result = await(std::move(committed), "the committed update must complete after cohort convergence");
    require(result && result->generation == 2 && result->rule_count == 1,
            "a terminal stop after commit must preserve the successful published result");
    harness.stop();
}

void test_successor_completes_a_command_after_postcommit_runner_failure()
{
    RegisteredWorkerControllerHarness harness{make_snapshot({"old.example"}, dns::server::kInitialFilterGeneration)};
    dns::server::FilterUpdateControllerTestPeer::inject_postcommit_failure_for_testing(harness.controller);

    auto committed = harness.controller.submit_replace({"survives-a.example"});
    require(eventually([&] { return harness.publication.current_generation() == 2; }), "the injected failure must happen after publication commit");
    require(eventually([&] { return harness.runner_finished.load(std::memory_order_acquire); }), "A must exit after the injected postcommit failure");
    harness.runner.join();
    require(harness.runner_exit.load(std::memory_order_relaxed) == dns::server::FilterRunnerExitCode::FatalExit,
            "the injected postcommit failure must be reported as a fatal A exit");
    require(committed.wait_for(0s) != std::future_status::ready, "A must leave the committed promise pending for its teardown successor");

    harness.acknowledge_current_generation();
    require(eventually([&] { return harness.publication.retirement_stats().last_converged_generation >= 2; }),
            "the exact cohort must converge before the successor completes its promise");
    require(harness.controller.complete_committed_by_successor() == dns::server::FilterSuccessorCompletionResult::Completed,
            "the teardown successor must claim and complete A's committed command");

    auto result = await(std::move(committed), "the successor-completed committed command must become ready");
    require(result && result->generation == 2 && result->rule_count == 1, "the teardown successor must preserve the successful committed result");
    harness.stop();
}

void test_runner_stop_closes_admission()
{
    ControllerHarness harness{make_snapshot({}, dns::server::kInitialFilterGeneration)};
    auto             &controller = harness.controller;

    harness.runner.request_stop();
    harness.runner.join();

    auto rejected = await(controller.submit_replace({"orphaned.example"}), "a stopped runner must reject instead of orphaning work");
    require_error(rejected, FilterUpdateErrorCode::ShuttingDown, "runner exit must atomically close update admission");
}

void test_builder_exception_does_not_stop_the_controller()
{
    std::atomic<size_t>             calls{0};
    FilterUpdateController::Builder throwing_builder =
        [&](std::span<const std::string> rules, FilterGeneration generation, std::stop_token stop_token)
    {
        if (calls.fetch_add(1, std::memory_order_relaxed) == 0)
            throw std::runtime_error{"injected builder failure"};
        return dns::server::build_filter_snapshot(rules, generation, stop_token);
    };

    ControllerHarness harness{make_snapshot({"stable.example"}, dns::server::kInitialFilterGeneration), std::move(throwing_builder)};
    auto             &controller = harness.controller;

    auto failed = await(controller.submit_replace({"throw.example"}), "an injected builder exception must complete");
    require_error(failed, FilterUpdateErrorCode::InternalError, "a builder exception must become an internal update error");
    require(controller.current_version().generation == 1, "a builder exception must not advance the generation");

    auto recovered = await(controller.submit_replace({"recovered.example"}), "the update controller must process work after a builder exception");
    require(recovered && recovered->generation == 2 && harness.publication.current_matches("recovered.example"),
            "the update controller must remain usable after a builder exception");

    harness.stop();
}

void test_generation_exhaustion_is_explicit()
{
    constexpr FilterGeneration maximum = std::numeric_limits<FilterGeneration>::max();
    ControllerHarness          harness{make_snapshot({"maximum.example"}, maximum)};
    auto                      &controller = harness.controller;

    auto exhausted = await(controller.submit_replace({"overflow.example"}), "generation exhaustion must complete");
    require_error(exhausted, FilterUpdateErrorCode::GenerationExhausted, "generation wraparound must be rejected explicitly");
    require(harness.publication.current_version().generation == maximum && harness.publication.current_matches("maximum.example"),
            "generation exhaustion must retain the existing snapshot");

    harness.stop();
}

void test_current_version_is_an_atomic_generation_rule_count_pair()
{
    ControllerHarness harness{make_snapshot({"odd.example"}, dns::server::kInitialFilterGeneration)};

    std::atomic<bool>         finished{false};
    std::atomic<bool>         mismatched{false};
    std::vector<std::jthread> readers;
    readers.reserve(4);
    for (size_t reader_index = 0; reader_index < 4; ++reader_index)
    {
        readers.emplace_back(
            [&]
            {
                size_t iterations = 0;
                while (!finished.load(std::memory_order_acquire))
                {
                    const auto version        = harness.controller.current_version();
                    const auto expected_count = version.generation % 2 == 0 ? 2U : 1U;
                    if (version.generation == 0 || version.rule_count != expected_count)
                    {
                        mismatched.store(true, std::memory_order_release);
                        break;
                    }
                    if ((++iterations & 63U) == 0)
                        std::this_thread::yield();
                }
            });
    }

    constexpr size_t update_count = 2'000;
    for (size_t index = 0; index < update_count; ++index)
    {
        const FilterGeneration   next_generation = static_cast<FilterGeneration>(index) + 2;
        std::vector<std::string> rules{"primary.example"};
        if (next_generation % 2 == 0)
            rules.emplace_back("secondary.example");
        auto result = await(harness.controller.submit_replace(std::move(rules)), "the version-pair stress update must complete");
        require(result && result->generation == next_generation, "the version-pair stress updates must publish consecutive generations");
        require(!mismatched.load(std::memory_order_acquire), "current_version must never combine fields from adjacent publications");
    }
    finished.store(true, std::memory_order_release);
    readers.clear();

    require(!mismatched.load(std::memory_order_acquire), "concurrent current_version reads must observe a coherent generation/rule-count pair");
    harness.stop();
}

void test_rule_and_queued_byte_limits()
{
    dns::server::FilterUpdateLimits limits{
        .maximum_rule_count            = 2,
        .maximum_normalized_rule_bytes = 9,
        .maximum_queued_rule_bytes     = 32,
    };
    ControllerHarness harness{make_snapshot({}, dns::server::kInitialFilterGeneration), {}, limits};

    auto exact = await(harness.controller.submit_replace({"abcdefg"}), "a canonical rule set exactly at the normalized-byte limit must complete");
    require(exact && exact->generation == 2, "the normalized-byte boundary itself must remain admissible");

    auto too_many = await(harness.controller.submit_replace({"a", "b", "c"}), "an over-count rule set must reject immediately");
    require_error(too_many, FilterUpdateErrorCode::RuleCountLimitExceeded, "rule count must be rejected before the command reaches the builder");
    require(too_many.error().actual == 3 && too_many.error().limit == 2, "count-limit diagnostics must report actual and limit");

    auto too_many_bytes =
        await(harness.controller.submit_replace({"abcdefgh"}), "a canonical rule one byte over the normalized limit must reject immediately");
    require_error(too_many_bytes, FilterUpdateErrorCode::RuleBytesLimitExceeded, "canonical rule bytes must have a hard per-command limit");
    require(too_many_bytes.error().actual == 10 && too_many_bytes.error().limit == 9,
            "normalized-byte diagnostics must report the exact boundary-plus-one measurement");
    require(harness.publication.current_version().generation == 2, "limit rejection must not consume a generation");
    harness.stop();

    std::binary_semaphore           entered_build{0};
    std::binary_semaphore           release_build{0};
    std::atomic<size_t>             queue_builder_calls{0};
    FilterUpdateController::Builder blocking_builder = [&](std::span<const std::string> rules, FilterGeneration generation, std::stop_token token)
    {
        if (queue_builder_calls.fetch_add(1, std::memory_order_relaxed) == 0)
        {
            entered_build.release();
            release_build.acquire();
        }
        return dns::server::build_filter_snapshot(rules, generation, token);
    };
    dns::server::FilterUpdateLimits queue_limits{
        .maximum_rule_count            = 10,
        .maximum_normalized_rule_bytes = 100,
        .maximum_queued_rule_bytes     = 8,
    };
    ControllerHarness queue_harness{make_snapshot({}, 1), std::move(blocking_builder), queue_limits};
    auto              inflight = queue_harness.controller.submit_replace({"run"});
    entered_build.acquire();
    auto queued   = queue_harness.controller.submit_replace({"12345678"});
    auto overflow = await(queue_harness.controller.submit_replace({"x"}), "queued byte overflow must reject immediately");
    require_error(overflow, FilterUpdateErrorCode::QueueBytesLimitExceeded,
                  "aggregate queued rule bytes must remain bounded independently of command count");
    require(overflow.error().actual == 9 && overflow.error().limit == 8,
            "queued-byte diagnostics must report exact aggregate actual and limit values");
    release_build.release();
    require(await(std::move(inflight), "in-flight bounded command must finish").has_value(), "in-flight bounded command must publish");
    require(await(std::move(queued), "queued bounded command must finish").has_value(), "queued bounded command must publish");
    queue_harness.stop();
}

} // namespace

int main()
{
    test_successful_reload_and_failed_reload_rollback();
    test_concurrent_reloads_are_serialized();
    test_builder_execution_is_fifo_and_serial();
    test_close_during_build_cancels_inflight_and_queued_requests();
    test_terminal_stop_does_not_reclassify_a_committed_update();
    test_successor_completes_a_command_after_postcommit_runner_failure();
    test_runner_stop_closes_admission();
    test_builder_exception_does_not_stop_the_controller();
    test_generation_exhaustion_is_explicit();
    test_current_version_is_an_atomic_generation_rule_count_pair();
    test_rule_and_queued_byte_limits();
    std::cout << "all filter reload tests passed\n";
    return EXIT_SUCCESS;
}
