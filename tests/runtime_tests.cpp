#include "runtime/Scheduler.h"
#include "runtime/Task.h"

#include <coroutine>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <stop_token>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace
{

using dns::runtime::Scheduler;
using dns::runtime::Task;

static_assert(!std::is_copy_constructible_v<Task<void>>);
static_assert(!std::is_copy_assignable_v<Task<void>>);
static_assert(std::is_nothrow_move_constructible_v<Task<void>>);
static_assert(std::is_nothrow_move_assignable_v<Task<void>>);

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "runtime test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

void require_spawned(Scheduler::SpawnResult result, std::string_view message)
{
    require(result == Scheduler::SpawnResult::Spawned, message);
}

void drain_ready(Scheduler &scheduler)
{
    size_t rounds = 0;
    while (scheduler.has_ready())
    {
        const auto result = scheduler.run_ready(32);
        require(result.resumed != 0, "a ready scheduler must make progress on its owner thread");
        require(++rounds < 1024, "test coroutine failed to reach an idle state");
    }
}

class DestructionProbe final
{
public:
    explicit DestructionProbe(int &destructions) noexcept
        : destructions_(&destructions)
    {
    }

    DestructionProbe(DestructionProbe &&other) noexcept
        : destructions_(std::exchange(other.destructions_, nullptr))
    {
    }

    DestructionProbe &operator=(DestructionProbe &&other) noexcept
    {
        if (this != &other)
        {
            destroy();
            destructions_ = std::exchange(other.destructions_, nullptr);
        }
        return *this;
    }

    ~DestructionProbe() { destroy(); }

    DestructionProbe(const DestructionProbe &) = delete;
    DestructionProbe &operator=(const DestructionProbe &) = delete;

private:
    void destroy() noexcept
    {
        if (destructions_ != nullptr)
        {
            ++*destructions_;
            destructions_ = nullptr;
        }
    }

    int *destructions_{nullptr};
};

Task<void> lazy_task(int &runs)
{
    ++runs;
    co_return;
}

Task<void> own_probe_forever(DestructionProbe probe)
{
    static_cast<void>(probe);
    co_await std::suspend_always{};
}

Task<int> ordered_child(std::vector<int> &order)
{
    order.push_back(2);
    co_await dns::runtime::this_coro::yield();
    order.push_back(3);
    co_return 41;
}

Task<void> ordered_parent(std::vector<int> &order, int &value)
{
    order.push_back(1);
    value = (co_await ordered_child(order)) + 1;
    order.push_back(4);
}

Task<std::unique_ptr<int>> move_only_child()
{
    co_return std::make_unique<int>(73);
}

Task<void> move_only_parent(int &value)
{
    auto result = co_await move_only_child();
    value = *result;
}

Task<int> failing_child()
{
    co_await dns::runtime::this_coro::yield();
    throw std::runtime_error{"child failure"};
}

Task<void> catch_child_failure(bool &caught)
{
    try
    {
        static_cast<void>(co_await failing_child());
    }
    catch (const std::runtime_error &)
    {
        caught = true;
    }
}

Task<void> uncaught_root_failure()
{
    throw std::runtime_error{"root failure"};
    co_return;
}

Task<void> yielding_task(int identity, std::vector<int> &order)
{
    order.push_back(identity * 10 + 1);
    co_await dns::runtime::this_coro::yield();
    order.push_back(identity * 10 + 2);
}

class ScheduleTwiceAwaiter final
{
public:
    ScheduleTwiceAwaiter(Scheduler &scheduler, Scheduler::ScheduleResult &first, Scheduler::ScheduleResult &second) noexcept
        : scheduler_(scheduler)
        , first_(first)
        , second_(second)
    {
    }

    [[nodiscard]] bool await_ready() const noexcept { return false; }

    template <dns::runtime::detail::TaskPromise Promise>
    bool await_suspend(std::coroutine_handle<Promise> handle) noexcept
    {
        auto &state = static_cast<dns::runtime::detail::TaskPromiseBase &>(handle.promise());
        first_ = scheduler_.schedule(state);
        second_ = scheduler_.schedule(state);
        return first_ == Scheduler::ScheduleResult::Scheduled;
    }

    void await_resume() const noexcept {}

private:
    Scheduler                  &scheduler_;
    Scheduler::ScheduleResult &first_;
    Scheduler::ScheduleResult &second_;
};

Task<void> duplicate_schedule_task(Scheduler &scheduler,
                                   Scheduler::ScheduleResult &first,
                                   Scheduler::ScheduleResult &second,
                                   int &runs)
{
    ++runs;
    co_await ScheduleTwiceAwaiter{scheduler, first, second};
    ++runs;
}

Task<void> nested_suspension(DestructionProbe parent_probe, DestructionProbe child_probe)
{
    static_cast<void>(parent_probe);
    co_await own_probe_forever(std::move(child_probe));
}

Task<void> completing_probe(DestructionProbe probe)
{
    static_cast<void>(probe);
    co_return;
}

Task<void> nested_completion(DestructionProbe parent_probe, DestructionProbe child_probe)
{
    static_cast<void>(parent_probe);
    co_await completing_probe(std::move(child_probe));
}

Task<void> observe_cancellation(bool &caught)
{
    co_await dns::runtime::this_coro::yield();
    try
    {
        co_await dns::runtime::this_coro::cancellation_point();
    }
    catch (const dns::runtime::OperationCancelled &)
    {
        caught = true;
    }
}

Task<void> yield_forever(DestructionProbe probe)
{
    static_cast<void>(probe);
    while (true)
        co_await dns::runtime::this_coro::yield();
}

Task<void> cancel_from_dispatch(Scheduler &scheduler, DestructionProbe probe, bool &returned)
{
    static_cast<void>(probe);
    returned = scheduler.cancel_all();
    co_await std::suspend_always{};
}

Task<void> shutdown_from_dispatch(Scheduler &scheduler, DestructionProbe probe, bool &returned)
{
    static_cast<void>(probe);
    returned = scheduler.shutdown() == 0;
    co_await std::suspend_always{};
}

Task<void> observe_shutdown_stop(bool &observed)
{
    co_await dns::runtime::this_coro::yield();
    const auto token = co_await dns::runtime::this_coro::stop_token();
    observed = token.stop_requested();
}

Task<void> observe_stop_callback_thread(bool &callback_ran, std::thread::id &callback_thread)
{
    const auto token = co_await dns::runtime::this_coro::stop_token();
    std::stop_callback callback{token, [&] {
                                    callback_thread = std::this_thread::get_id();
                                    callback_ran = true;
                                }};
    co_await dns::runtime::this_coro::yield();
}

Task<void> stop_during_dispatch(std::stop_source &source, bool &caught)
{
    std::jthread stop_requester{[&] { source.request_stop(); }};
    stop_requester.join();
    try
    {
        co_await dns::runtime::this_coro::cancellation_point();
    }
    catch (const dns::runtime::OperationCancelled &)
    {
        caught = true;
    }
}

void test_lazy_move_and_unstarted_destruction()
{
    int runs = 0;
    auto original = lazy_task(runs);
    require(runs == 0, "Task must remain lazy when constructed");
    auto moved = std::move(original);
    require(!original && moved && runs == 0, "moving a Task must transfer its sole frame without starting it");

    Scheduler scheduler;
    require(scheduler.start(), "scheduler fixture must start");
    require_spawned(scheduler.spawn(std::move(moved)), "scheduler must adopt a valid root Task");
    require(!moved && scheduler.active_count() == 1, "spawn must transfer root ownership to the scheduler");
    require(scheduler.run_ready(1).resumed == 1 && runs == 1, "a scheduled lazy Task must run exactly once");
    require(scheduler.active_count() == 0, "a completed root frame must be reclaimed immediately");
    static_cast<void>(scheduler.shutdown());

    int destructions = 0;
    {
        auto unstarted = own_probe_forever(DestructionProbe{destructions});
        require(static_cast<bool>(unstarted), "unstarted Task fixture must own its frame");
    }
    require(destructions == 1, "destroying an unstarted Task must destroy its frame exactly once");
}

void test_nested_results_and_exceptions()
{
    Scheduler scheduler;
    require(scheduler.start(), "nested scheduler fixture must start");

    std::vector<int> order;
    int value = 0;
    require_spawned(scheduler.spawn(ordered_parent(order, value)), "nested parent must spawn");
    require(scheduler.run_ready(1).resumed == 1 && order == std::vector<int>{1}, "parent must schedule rather than inline-resume its child");
    require(scheduler.run_ready(1).resumed == 1 && order == std::vector<int>({1, 2}), "child must begin on a scheduler turn");
    require(scheduler.run_ready(1).resumed == 1 && order == std::vector<int>({1, 2, 3}), "yielded child must resume through the ready queue");
    require(scheduler.run_ready(1).resumed == 1 && order == std::vector<int>({1, 2, 3, 4}) && value == 42,
            "child result and continuation must return to the parent");

    int move_only_value = 0;
    require_spawned(scheduler.spawn(move_only_parent(move_only_value)), "move-only result parent must spawn");
    drain_ready(scheduler);
    require(move_only_value == 73, "Task<T> must return move-only values");

    bool caught = false;
    require_spawned(scheduler.spawn(catch_child_failure(caught)), "exception parent must spawn");
    drain_ready(scheduler);
    require(caught, "a child exception must be rethrown at the parent co_await expression");
    require(scheduler.unhandled_root_exceptions() == 0, "a caught child exception must not become a root error");

    require_spawned(scheduler.spawn(uncaught_root_failure()), "failing root must spawn");
    drain_ready(scheduler);
    require(scheduler.unhandled_root_exceptions() == 1 && scheduler.last_unhandled_exception(),
            "an uncaught root exception must be recorded before its frame is reclaimed");
    static_cast<void>(scheduler.shutdown());
}

void test_fifo_budget_and_duplicate_suppression()
{
    Scheduler scheduler;
    require(scheduler.start(), "FIFO scheduler fixture must start");

    std::vector<int> order;
    require_spawned(scheduler.spawn(yielding_task(1, order)), "first yielding task must spawn");
    require_spawned(scheduler.spawn(yielding_task(2, order)), "second yielding task must spawn");
    require(scheduler.ready_count() == 2, "spawned roots must enter the ready queue");

    const auto none = scheduler.run_ready(0);
    require(none.resumed == 0 && none.has_ready, "a zero resume budget must not consume ready work");
    const auto first_round = scheduler.run_ready(2);
    require(first_round.resumed == 2 && first_round.has_ready && order == std::vector<int>({11, 21}),
            "the resume budget must count queue pops and preserve FIFO order");
    const auto second_round = scheduler.run_ready(2);
    require(second_round.resumed == 2 && !second_round.has_ready && order == std::vector<int>({11, 21, 12, 22}),
            "yielded tasks must re-enter the tail fairly");

    Scheduler::ScheduleResult first = Scheduler::ScheduleResult::NotRunning;
    Scheduler::ScheduleResult second = Scheduler::ScheduleResult::NotRunning;
    int runs = 0;
    require_spawned(scheduler.spawn(duplicate_schedule_task(scheduler, first, second, runs)), "duplicate fixture must spawn");
    require(scheduler.run_ready(1).resumed == 1 && runs == 1, "duplicate fixture must suspend after its first execution");
    require(first == Scheduler::ScheduleResult::Scheduled && second == Scheduler::ScheduleResult::Duplicate && scheduler.ready_count() == 1,
            "the same suspended frame must not be queued twice");
    require(scheduler.run_ready(1).resumed == 1 && runs == 2 && scheduler.active_count() == 0,
            "duplicate suppression must still permit one valid continuation");
    static_cast<void>(scheduler.shutdown());
}

void test_cancellation_and_structured_cleanup()
{
    int queued_parent_destructions = 0;
    int queued_child_destructions = 0;
    Scheduler queued_child_cleanup;
    require(queued_child_cleanup.start(), "queued-child scheduler fixture must start");
    require_spawned(queued_child_cleanup.spawn(
                        nested_suspension(DestructionProbe{queued_parent_destructions}, DestructionProbe{queued_child_destructions})),
                    "queued-child fixture must spawn");
    require(queued_child_cleanup.run_ready(1).resumed == 1 && queued_child_cleanup.ready_count() == 1,
            "parent suspension must leave its borrowed child in the ready queue");
    require(queued_child_cleanup.cancel_all(), "queued-child cancellation must be accepted");
    require(queued_parent_destructions == 1 && queued_child_destructions == 1 && !queued_child_cleanup.has_ready(),
            "cancellation must clear a queued child handle before destroying its owning root");
    static_cast<void>(queued_child_cleanup.shutdown());

    int queued_continuation_parent_destructions = 0;
    int completed_child_destructions = 0;
    Scheduler queued_parent_cleanup;
    require(queued_parent_cleanup.start(), "queued-parent scheduler fixture must start");
    require_spawned(queued_parent_cleanup.spawn(nested_completion(DestructionProbe{queued_continuation_parent_destructions},
                                                                  DestructionProbe{completed_child_destructions})),
                    "queued-parent fixture must spawn");
    require(queued_parent_cleanup.run_ready(1).resumed == 1 && queued_parent_cleanup.run_ready(1).resumed == 1 &&
                queued_parent_cleanup.ready_count() == 1,
            "a completed child must enqueue its suspended parent continuation");
    require(queued_parent_cleanup.cancel_all(), "queued-parent cancellation must be accepted");
    require(queued_continuation_parent_destructions == 1 && completed_child_destructions == 1 && !queued_parent_cleanup.has_ready(),
            "cancellation must clear a queued parent before recursively destroying its completed child");
    static_cast<void>(queued_parent_cleanup.shutdown());

    int parent_destructions = 0;
    int child_destructions = 0;
    {
        Scheduler scheduler;
        require(scheduler.start(), "cleanup scheduler fixture must start");
        require_spawned(scheduler.spawn(nested_suspension(DestructionProbe{parent_destructions}, DestructionProbe{child_destructions})),
                        "nested suspension fixture must spawn");
        require(scheduler.run_ready(1).resumed == 1, "parent must start and schedule its child");
        require(scheduler.run_ready(1).resumed == 1 && !scheduler.has_ready() && scheduler.active_count() == 1,
                "a permanently suspended child must remain owned through its root");
        require(scheduler.cancel_all(), "owner-thread cancellation must be accepted");
        require(scheduler.active_count() == 0 && !scheduler.has_ready(), "cancel_all must clear borrowed ready entries before destroying roots");
        require(scheduler.cancel_all(), "repeated owner-thread cancellation must be idempotent");
    }
    require(parent_destructions == 1 && child_destructions == 1,
            "hard cancellation must destroy suspended parent and child frames exactly once");

    std::stop_source stop_source;
    Scheduler cancellation_scheduler;
    require(cancellation_scheduler.start(stop_source.get_token()), "cancellation scheduler fixture must start");
    bool caught = false;
    require_spawned(cancellation_scheduler.spawn(observe_cancellation(caught)), "cancellation observer must spawn");
    require(cancellation_scheduler.run_ready(1).resumed == 1 && cancellation_scheduler.has_ready(),
            "observer must reach a scheduler-owned yield point");
    stop_source.request_stop();
    require(cancellation_scheduler.run_ready(1).resumed == 1 && caught && cancellation_scheduler.active_count() == 0,
            "a requested stop must be visible at a cooperative cancellation point");
    require(cancellation_scheduler.spawn(lazy_task(parent_destructions)) == Scheduler::SpawnResult::NotAccepting,
            "a stopped scheduler must reject new roots");
    static_cast<void>(cancellation_scheduler.shutdown());

    std::stop_source callback_stop_source;
    Scheduler callback_scheduler;
    require(callback_scheduler.start(callback_stop_source.get_token()), "stop callback scheduler fixture must start");
    bool callback_ran = false;
    std::thread::id callback_thread{};
    const auto owner_thread = std::this_thread::get_id();
    require_spawned(callback_scheduler.spawn(observe_stop_callback_thread(callback_ran, callback_thread)),
                    "stop callback observer must spawn");
    require(callback_scheduler.run_ready(1).resumed == 1 && callback_scheduler.has_ready(),
            "stop callback observer must register before yielding");
    std::jthread stop_requester{[&] { callback_stop_source.request_stop(); }};
    stop_requester.join();
    require(!callback_ran, "external stop propagation must not execute internal callbacks on the requesting thread");
    require(callback_scheduler.run_ready(1).resumed == 1 && callback_ran && callback_thread == owner_thread,
            "the scheduler owner must propagate external stop before resuming ready work");
    static_cast<void>(callback_scheduler.shutdown());

    std::stop_source in_dispatch_stop_source;
    Scheduler in_dispatch_stop_scheduler;
    require(in_dispatch_stop_scheduler.start(in_dispatch_stop_source.get_token()), "in-dispatch stop scheduler fixture must start");
    bool in_dispatch_cancelled = false;
    require_spawned(in_dispatch_stop_scheduler.spawn(stop_during_dispatch(in_dispatch_stop_source, in_dispatch_cancelled)),
                    "in-dispatch cancellation fixture must spawn");
    require(in_dispatch_stop_scheduler.run_ready(1).resumed == 1 && in_dispatch_cancelled,
            "a cancellation point must refresh an external stop that arrived during the same dispatch");
    static_cast<void>(in_dispatch_stop_scheduler.shutdown());

    int queued_destructions = 0;
    Scheduler bounded_shutdown;
    require(bounded_shutdown.start(), "bounded shutdown scheduler fixture must start");
    require_spawned(bounded_shutdown.spawn(yield_forever(DestructionProbe{queued_destructions})), "endless yield fixture must spawn");
    require(bounded_shutdown.shutdown(3) == 3, "shutdown must respect its cooperative resume budget");
    require(queued_destructions == 1 && bounded_shutdown.active_count() == 0 && !bounded_shutdown.has_ready(),
            "shutdown must hard-cancel tasks that ignore cooperative cancellation");

    int destructor_cleanup = 0;
    {
        Scheduler automatic_cleanup;
        require(automatic_cleanup.start(), "destructor cleanup scheduler fixture must start");
        require_spawned(automatic_cleanup.spawn(own_probe_forever(DestructionProbe{destructor_cleanup})), "destructor fixture must spawn");
        require(automatic_cleanup.run_ready(1).resumed == 1, "destructor fixture must become suspended");
    }
    require(destructor_cleanup == 1, "Scheduler destruction must reclaim a remaining root frame");

    int wrong_thread_destructions = 0;
    Scheduler wrong_thread_cleanup;
    require(wrong_thread_cleanup.start(), "wrong-thread scheduler fixture must start");
    require_spawned(wrong_thread_cleanup.spawn(own_probe_forever(DestructionProbe{wrong_thread_destructions})),
                    "wrong-thread cleanup fixture must spawn");
    bool wrong_thread_rejected = false;
    std::jthread foreign_cleanup{[&] { wrong_thread_rejected = !wrong_thread_cleanup.cancel_all(); }};
    foreign_cleanup.join();
    require(wrong_thread_rejected && wrong_thread_cleanup.active_count() == 1 && wrong_thread_destructions == 0,
            "a non-owner thread must not destroy scheduler-owned frames");
    require(wrong_thread_cleanup.cancel_all(), "the owner thread must still be able to cancel after a rejected foreign call");
    require(wrong_thread_destructions == 1, "owner-thread cleanup must reclaim the retained root");
    static_cast<void>(wrong_thread_cleanup.shutdown());

    int reentrant_cancel_destructions = 0;
    bool cancel_returned = false;
    Scheduler reentrant_cancel;
    require(reentrant_cancel.start(), "reentrant cancellation scheduler fixture must start");
    require_spawned(reentrant_cancel.spawn(cancel_from_dispatch(reentrant_cancel, DestructionProbe{reentrant_cancel_destructions}, cancel_returned)),
                    "reentrant cancellation fixture must spawn");
    require(reentrant_cancel.run_ready(1).resumed == 1 && cancel_returned && reentrant_cancel_destructions == 1 &&
                reentrant_cancel.active_count() == 0,
            "cancel_all called inside resume must defer frame destruction until dispatch returns");
    static_cast<void>(reentrant_cancel.shutdown());

    int reentrant_shutdown_destructions = 0;
    bool shutdown_returned = false;
    Scheduler reentrant_shutdown;
    require(reentrant_shutdown.start(), "reentrant shutdown scheduler fixture must start");
    require_spawned(reentrant_shutdown.spawn(
                        shutdown_from_dispatch(reentrant_shutdown, DestructionProbe{reentrant_shutdown_destructions}, shutdown_returned)),
                    "reentrant shutdown fixture must spawn");
    require(reentrant_shutdown.run_ready(1).resumed == 1 && shutdown_returned && reentrant_shutdown_destructions == 1 &&
                reentrant_shutdown.active_count() == 0,
            "shutdown called inside resume must deactivate only after dispatch returns");

    bool shutdown_stop_observed = false;
    Scheduler shutdown_stop;
    require(shutdown_stop.start(), "shutdown stop-token scheduler fixture must start");
    require_spawned(shutdown_stop.spawn(observe_shutdown_stop(shutdown_stop_observed)), "shutdown observer must spawn");
    require(shutdown_stop.run_ready(1).resumed == 1 && shutdown_stop.has_ready(), "shutdown observer must first yield");
    require(shutdown_stop.shutdown(1) == 1 && shutdown_stop_observed && shutdown_stop.active_count() == 0,
            "shutdown must request cooperative cancellation before draining ready work");

    int rejected_task_destructions = 0;
    Scheduler closed_scheduler;
    require(closed_scheduler.start(), "closed scheduler fixture must start");
    require(closed_scheduler.close(), "owner thread must be able to close root admission");
    {
        auto rejected = own_probe_forever(DestructionProbe{rejected_task_destructions});
        require(closed_scheduler.spawn(std::move(rejected)) == Scheduler::SpawnResult::NotAccepting && rejected,
                "a rejected spawn must leave frame ownership with its Task argument");
    }
    require(rejected_task_destructions == 1, "destroying a rejected Task must reclaim its frame exactly once");
    static_cast<void>(closed_scheduler.shutdown());
}

} // namespace

int main()
{
    test_lazy_move_and_unstarted_destruction();
    test_nested_results_and_exceptions();
    test_fifo_budget_and_duplicate_suppression();
    test_cancellation_and_structured_cleanup();
    std::cout << "all coroutine runtime tests passed\n";
    return EXIT_SUCCESS;
}
