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

namespace
{

using namespace std::chrono_literals;
using dns::server::FilterGeneration;
using dns::server::FilterSnapshot;
using dns::server::FilterUpdateController;
using dns::server::FilterUpdateErrorCode;
using dns::server::FilterUpdateFuture;
using dns::server::FilterUpdateResult;

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "filter reload test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

FilterSnapshot make_snapshot(std::vector<std::string> rules, FilterGeneration generation)
{
    auto snapshot = dns::server::build_filter_snapshot(rules, generation);
    require(snapshot.has_value(), "filter reload fixture snapshot must build");
    return std::move(*snapshot);
}

FilterUpdateResult await(FilterUpdateFuture future, std::string_view message)
{
    require(future.wait_for(2s) == std::future_status::ready, message);
    return future.get();
}

void stop_controller(FilterUpdateController &controller, std::jthread &runner)
{
    controller.close();
    runner.request_stop();
    runner.join();
}

void require_error(const FilterUpdateResult &result, FilterUpdateErrorCode code, std::string_view message)
{
    require(!result && result.error().code == code, message);
}

void test_successful_reload_and_failed_reload_rollback()
{
    FilterUpdateController controller{make_snapshot({"old.example"}, dns::server::kInitialFilterGeneration)};
    std::jthread           runner{[&controller](std::stop_token token) { controller.run(token); }};

    const auto initial = controller.current_version();
    require(initial && initial->generation == 1 && initial->rule_count == 1, "initial snapshot must be generation one");

    auto replaced = await(controller.submit_replace({"new.example", "second.example"}), "a valid reload must complete");
    require(replaced && replaced->generation == 2 && replaced->rule_count == 2, "a successful reload must publish generation two");

    const auto generation_two = controller.snapshot();
    require(generation_two && generation_two->generation == 2 && generation_two->blocklist.matches("child.new.example") &&
                generation_two->blocklist.matches("second.example") && !generation_two->blocklist.matches("old.example"),
            "the new generation must atomically replace the complete rule set");

    auto invalid = await(controller.submit_replace({"valid.example", "*.bad.example"}), "an invalid reload must complete with an error");
    require_error(invalid, FilterUpdateErrorCode::BuildFailed, "an invalid rule must report a build failure");
    require(invalid.error().build_error && invalid.error().build_error->code == Filter::BlocklistBuildErrorCode::WildcardNotSupported &&
                invalid.error().build_error->rule_index == 1,
            "a build failure must retain the exact rule error");
    require(controller.snapshot() == generation_two, "a failed reload must retain the exact old snapshot object");

    auto after_failure = await(controller.submit_replace({"third.example"}), "a valid reload after failure must complete");
    require(after_failure && after_failure->generation == 3 && after_failure->rule_count == 1, "a failed build must not consume a generation");

    stop_controller(controller, runner);
}

void test_concurrent_reloads_are_serialized()
{
    FilterUpdateController controller{make_snapshot({}, dns::server::kInitialFilterGeneration)};
    std::jthread           runner{[&controller](std::stop_token token) { controller.run(token); }};

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

    const auto final_snapshot = controller.snapshot();
    const bool first_won      = first_generation == 3;
    require(final_snapshot && final_snapshot->generation == 3 &&
                final_snapshot->blocklist.matches(first_won ? "first.concurrent" : "second.concurrent") &&
                !final_snapshot->blocklist.matches(first_won ? "second.concurrent" : "first.concurrent"),
            "the final snapshot must match the request that received the final generation");

    stop_controller(controller, runner);
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

    FilterUpdateController controller{make_snapshot({}, dns::server::kInitialFilterGeneration), std::move(ordered_builder)};
    std::jthread           runner{[&controller](std::stop_token token) { controller.run(token); }};

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
            "the manager must invoke at most one snapshot builder at a time");
    require(controller.snapshot()->blocklist.matches("second.fifo") && !controller.snapshot()->blocklist.matches("first.fifo"),
            "the final FIFO generation must contain only the second replacement rule set");

    stop_controller(controller, runner);
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

    const auto             initial = make_snapshot({"stable.example"}, dns::server::kInitialFilterGeneration);
    FilterUpdateController controller{initial, std::move(blocking_builder)};
    std::jthread           runner{[&controller](std::stop_token token) { controller.run(token); }};

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
    require(controller.snapshot() == initial, "closing during a build must preserve the published snapshot");
    runner.join();

    auto rejected = await(controller.submit_replace({"late.example"}), "a reload submitted after close must be immediately ready");
    require_error(rejected, FilterUpdateErrorCode::ShuttingDown, "a closed controller must reject new work");
}

void test_runner_stop_closes_admission()
{
    FilterUpdateController controller{make_snapshot({}, dns::server::kInitialFilterGeneration)};
    std::jthread           runner{[&controller](std::stop_token token) { controller.run(token); }};

    runner.request_stop();
    runner.join();

    auto rejected = await(controller.submit_replace({"orphaned.example"}), "a stopped runner must reject instead of orphaning work");
    require_error(rejected, FilterUpdateErrorCode::ShuttingDown, "runner exit must atomically close update admission");
}

void test_builder_exception_does_not_stop_the_manager()
{
    std::atomic<size_t>             calls{0};
    FilterUpdateController::Builder throwing_builder =
        [&](std::span<const std::string> rules, FilterGeneration generation, std::stop_token stop_token)
    {
        if (calls.fetch_add(1, std::memory_order_relaxed) == 0)
            throw std::runtime_error{"injected builder failure"};
        return dns::server::build_filter_snapshot(rules, generation, stop_token);
    };

    FilterUpdateController controller{make_snapshot({"stable.example"}, dns::server::kInitialFilterGeneration), std::move(throwing_builder)};
    std::jthread           runner{[&controller](std::stop_token token) { controller.run(token); }};

    auto failed = await(controller.submit_replace({"throw.example"}), "an injected builder exception must complete");
    require_error(failed, FilterUpdateErrorCode::InternalError, "a builder exception must become an internal update error");
    require(controller.current_version()->generation == 1, "a builder exception must not advance the generation");

    auto recovered = await(controller.submit_replace({"recovered.example"}), "the manager must process work after a builder exception");
    require(recovered && recovered->generation == 2 && controller.snapshot()->blocklist.matches("recovered.example"),
            "the manager must remain usable after a builder exception");

    stop_controller(controller, runner);
}

void test_generation_exhaustion_is_explicit()
{
    constexpr FilterGeneration maximum = std::numeric_limits<FilterGeneration>::max();
    const auto                 initial = make_snapshot({"maximum.example"}, maximum);
    FilterUpdateController     controller{initial};
    std::jthread               runner{[&controller](std::stop_token token) { controller.run(token); }};

    auto exhausted = await(controller.submit_replace({"overflow.example"}), "generation exhaustion must complete");
    require_error(exhausted, FilterUpdateErrorCode::GenerationExhausted, "generation wraparound must be rejected explicitly");
    require(controller.snapshot() == initial, "generation exhaustion must retain the existing snapshot");

    stop_controller(controller, runner);
}

} // namespace

int main()
{
    test_successful_reload_and_failed_reload_rollback();
    test_concurrent_reloads_are_serialized();
    test_builder_execution_is_fifo_and_serial();
    test_close_during_build_cancels_inflight_and_queued_requests();
    test_runner_stop_closes_admission();
    test_builder_exception_does_not_stop_the_manager();
    test_generation_exhaustion_is_explicit();
    std::cout << "all filter reload tests passed\n";
    return EXIT_SUCCESS;
}
