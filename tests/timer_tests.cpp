#include "runtime/Scheduler.h"
#include "runtime/Task.h"
#include "runtime/TimerQueue.h"

#include <chrono>
#include <climits>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stop_token>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace
{

using dns::runtime::OperationCancelled;
using dns::runtime::Scheduler;
using dns::runtime::Task;
using dns::runtime::TimerQueue;
using namespace std::chrono_literals;

static_assert(!std::is_copy_constructible_v<TimerQueue>);
static_assert(!std::is_move_constructible_v<TimerQueue>);
static_assert(!std::is_copy_constructible_v<dns::runtime::SleepAwaiter>);
static_assert(!std::is_move_constructible_v<dns::runtime::SleepAwaiter>);

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "timer test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

void require_spawned(Scheduler::SpawnResult result, std::string_view message)
{
    require(result == Scheduler::SpawnResult::Spawned, message);
}

class DestructionProbe final
{
public:
    explicit DestructionProbe(size_t &destructions) noexcept
        : destructions_(&destructions)
    {
    }

    DestructionProbe(DestructionProbe &&other) noexcept
        : destructions_(std::exchange(other.destructions_, nullptr))
    {
    }

    ~DestructionProbe()
    {
        if (destructions_ != nullptr)
            ++*destructions_;
    }

    DestructionProbe(const DestructionProbe &)            = delete;
    DestructionProbe &operator=(const DestructionProbe &) = delete;
    DestructionProbe &operator=(DestructionProbe &&)      = delete;

private:
    size_t *destructions_{nullptr};
};

Task<void> record_after(TimerQueue &timers, TimerQueue::TimePoint deadline, size_t identity, std::vector<size_t> &order)
{
    co_await timers.sleep_until(deadline);
    order.push_back(identity);
}

Task<void> record_after_delay(TimerQueue &timers, TimerQueue::Duration delay, bool &completed)
{
    co_await timers.sleep_for(delay);
    completed = true;
}

Task<void> catch_timer_cancellation(TimerQueue &timers, TimerQueue::TimePoint deadline, bool &caught, std::thread::id *resume_thread = nullptr)
{
    try
    {
        co_await timers.sleep_until(deadline);
    }
    catch (const OperationCancelled &)
    {
        caught = true;
        if (resume_thread != nullptr)
            *resume_thread = std::this_thread::get_id();
    }
}

Task<void> catch_timer_failure(TimerQueue &timers, bool &caught)
{
    try
    {
        co_await timers.sleep_until(TimerQueue::TimePoint{});
    }
    catch (const std::logic_error &)
    {
        caught = true;
    }
}

Task<void> sleeping_probe(TimerQueue &timers, TimerQueue::TimePoint deadline, DestructionProbe probe, bool *completed = nullptr)
{
    static_cast<void>(probe);
    co_await timers.sleep_until(deadline);
    if (completed != nullptr)
        *completed = true;
}

Task<void> cancellable_probe(TimerQueue &timers, TimerQueue::TimePoint deadline, DestructionProbe probe, size_t &caught)
{
    static_cast<void>(probe);
    try
    {
        co_await timers.sleep_until(deadline);
    }
    catch (const OperationCancelled &)
    {
        ++caught;
    }
}

Task<void> sleeping_child(TimerQueue &timers, TimerQueue::TimePoint deadline)
{
    co_await timers.sleep_until(deadline);
}

Task<void> parent_catches_child_cancellation(TimerQueue &timers, TimerQueue::TimePoint deadline, bool &caught)
{
    try
    {
        co_await sleeping_child(timers, deadline);
    }
    catch (const OperationCancelled &)
    {
        caught = true;
    }
}

void test_runtime_restart()
{
    TimerQueue timers;
    Scheduler  scheduler;
    require(scheduler.start(), "restart scheduler must start the first time");
    require(timers.start(scheduler), "restart timer queue must start the first time");
    require(timers.close(), "restart timer queue must close the first time");
    require(scheduler.close(), "restart scheduler must close the first time");
    static_cast<void>(scheduler.shutdown());
    require(timers.stop() && !timers.running(), "an empty stopped timer queue must release its Scheduler binding");

    require(scheduler.start(), "restart scheduler must start the second time");
    require(timers.start(scheduler), "restart timer queue must start the second time");
    std::vector<size_t> order;
    const auto          deadline = TimerQueue::TimePoint{} + 5s;
    require_spawned(scheduler.spawn(record_after(timers, deadline, 7, order)), "timer after restart must spawn");
    require(scheduler.run_ready(1).resumed == 1 && timers.expire(deadline).dispatched == 1 && scheduler.run_ready(1).resumed == 1 &&
                order == std::vector<size_t>{7},
            "restarted runtime must dispatch a timer normally");
    require(timers.close(), "restarted timer queue must close cleanly");
    static_cast<void>(scheduler.shutdown());
    require(timers.stop(), "restarted timer queue must stop cleanly");
}

void test_sleep_for_and_binding_errors()
{
    {
        TimerQueue timers;
        Scheduler  scheduler;
        require(!timers.start(scheduler), "timer queue must reject a Scheduler that has not started");
        require(scheduler.start(), "affinity scheduler must start");
        bool         wrong_thread_rejected = false;
        std::jthread foreign_start{[&] { wrong_thread_rejected = !timers.start(scheduler); }};
        foreign_start.join();
        require(wrong_thread_rejected && timers.start(scheduler), "timer queue must bind only from its running Scheduler's owner thread");
        static_cast<void>(scheduler.shutdown());
        require(timers.stop(), "affinity timer queue must stop");
    }

    {
        TimerQueue timers;
        Scheduler  scheduler;
        require(scheduler.start(), "sleep_for scheduler must start");
        require(timers.start(scheduler), "sleep_for timer queue must start");

        bool zero_completed     = false;
        bool negative_completed = false;
        require_spawned(scheduler.spawn(record_after_delay(timers, TimerQueue::Duration::zero(), zero_completed)), "zero-duration sleep must spawn");
        require_spawned(scheduler.spawn(record_after_delay(timers, -1ms, negative_completed)), "negative-duration sleep must spawn");
        require(scheduler.run_ready(2).resumed == 2 && timers.size() == 2 && timers.wait_timeout(TimerQueue::Clock::now()) == 0,
                "non-positive sleeps must arm as immediately due without inline resume");
        require(timers.expire(TimerQueue::TimePoint::max()).dispatched == 2 && !zero_completed && !negative_completed,
                "non-positive sleep expiry must only enqueue its waiters");
        require(scheduler.run_ready(2).resumed == 2 && zero_completed && negative_completed, "non-positive sleeps must complete through Scheduler");

        bool maximum_completed = false;
        require_spawned(scheduler.spawn(record_after_delay(timers, TimerQueue::Duration::max(), maximum_completed)),
                        "maximum-duration sleep must spawn");
        require(scheduler.run_ready(1).resumed == 1 && timers.next_deadline() == TimerQueue::TimePoint::max(),
                "sleep_for must saturate an overflowing deadline at TimePoint::max");
        require(!timers.stop(), "an armed timer queue must reject stop rather than orphaning a node");
        require(scheduler.cancel_all() && timers.empty() && !maximum_completed, "hard cancellation must unlink a saturated sleep_for timer");
        static_cast<void>(scheduler.shutdown());
        require(timers.stop(), "empty sleep_for timer queue must stop");
    }

    {
        TimerQueue timers;
        Scheduler  scheduler;
        require(scheduler.start(), "unbound timer scheduler must start");
        bool caught = false;
        require_spawned(scheduler.spawn(catch_timer_failure(timers, caught)), "unbound timer task must spawn");
        require(scheduler.run_ready(1).resumed == 1 && caught && timers.empty(),
                "using a timer queue before start must surface a logic error without suspension");
        static_cast<void>(scheduler.shutdown());
    }

    {
        TimerQueue timers;
        Scheduler  owner_scheduler;
        Scheduler  other_scheduler;
        require(owner_scheduler.start(), "timer owner scheduler must start");
        require(timers.start(owner_scheduler), "scheduler-bound timer queue must start");
        require(other_scheduler.start(), "other scheduler must start");
        bool caught = false;
        require_spawned(other_scheduler.spawn(catch_timer_failure(timers, caught)), "wrong-scheduler timer task must spawn");
        require(other_scheduler.run_ready(1).resumed == 1 && caught && timers.empty(),
                "a timer queue must reject a coroutine owned by another Scheduler");
        static_cast<void>(other_scheduler.shutdown());
        static_cast<void>(owner_scheduler.shutdown());
        require(timers.stop(), "wrong-scheduler fixture timer queue must stop");
    }
}

void test_deadline_order_and_stable_fifo()
{
    TimerQueue timers;
    Scheduler  scheduler;
    require(scheduler.start(), "deadline scheduler must start");
    require(timers.start(scheduler), "deadline timer queue must start");

    const auto          base = TimerQueue::TimePoint{} + 10s;
    std::vector<size_t> order;
    require_spawned(scheduler.spawn(record_after(timers, base + 30ms, 1, order)), "30ms timer must spawn");
    require_spawned(scheduler.spawn(record_after(timers, base + 10ms, 2, order)), "10ms timer must spawn");
    require_spawned(scheduler.spawn(record_after(timers, base + 20ms, 3, order)), "20ms timer must spawn");

    require(scheduler.run_ready(3).resumed == 3 && !scheduler.has_ready() && timers.size() == 3, "initial coroutine turns must arm three timers");
    require(timers.next_deadline() == base + 10ms, "heap root must expose the earliest deadline");
    require(timers.wait_timeout(base) == 10, "timer timeout must reflect the nearest deadline");
    require(timers.expire(base + 9ms).dispatched == 0 && order.empty(), "a timer must not fire before its deadline");

    const auto first = timers.expire(base + 10ms);
    require(first.dispatched == 1 && first.schedule_failures == 0 && !first.has_due && scheduler.ready_count() == 1 && order.empty(),
            "expiry must enqueue exactly one timer without inline resume");
    require(scheduler.run_ready(1).resumed == 1 && order == std::vector<size_t>{2}, "the earliest timer must resume first");

    require(timers.expire(base + 20ms).dispatched == 1 && scheduler.run_ready(1).resumed == 1 && order == std::vector<size_t>({2, 3}),
            "the second deadline must resume next");
    require(timers.expire(base + 30ms).dispatched == 1 && scheduler.run_ready(1).resumed == 1 && order == std::vector<size_t>({2, 3, 1}) &&
                timers.empty(),
            "all differently ordered deadlines must complete in time order");

    const auto shared_deadline = base + 1s;
    require_spawned(scheduler.spawn(record_after(timers, shared_deadline, 4, order)), "first equal timer must spawn");
    require_spawned(scheduler.spawn(record_after(timers, shared_deadline, 5, order)), "second equal timer must spawn");
    require_spawned(scheduler.spawn(record_after(timers, shared_deadline, 6, order)), "third equal timer must spawn");
    require(scheduler.run_ready(3).resumed == 3 && timers.size() == 3, "equal-deadline timers must arm");

    const auto equal = timers.expire(shared_deadline);
    require(equal.dispatched == 3 && equal.schedule_failures == 0 && scheduler.ready_count() == 3,
            "one expiry pass must enqueue all equal-deadline timers");
    require(scheduler.run_ready(1).resumed == 1 && order.back() == 4, "equal deadline FIFO must resume the first registration first");
    require(scheduler.run_ready(1).resumed == 1 && order.back() == 5, "equal deadline FIFO must resume the second registration second");
    require(scheduler.run_ready(1).resumed == 1 && order.back() == 6, "equal deadline FIFO must resume the third registration third");

    require(timers.close(), "deadline timer queue must close");
    require(scheduler.close(), "deadline scheduler must close");
    static_cast<void>(scheduler.shutdown());
}

void test_timeout_rounding_and_budgets()
{
    {
        TimerQueue timers;
        Scheduler  scheduler;
        require(scheduler.start(), "timeout scheduler must start");
        require(timers.start(scheduler), "timeout timer queue must start");
        require(timers.wait_timeout(TimerQueue::TimePoint{}) == -1, "an empty timer queue must permit an infinite wait");

        const auto          base     = TimerQueue::TimePoint{} + 20s;
        const auto          deadline = base + 1'000'001ns;
        std::vector<size_t> order;
        require_spawned(scheduler.spawn(record_after(timers, deadline, 1, order)), "rounding timer must spawn");
        require(scheduler.run_ready(1).resumed == 1, "rounding timer must arm");
        require(timers.wait_timeout(base) == 2, "a fractional millisecond timeout must round upward");
        require(timers.wait_timeout(deadline - 1ns) == 1, "a remaining nanosecond must still wait one millisecond");
        require(timers.wait_timeout(deadline) == 0 && timers.wait_timeout(deadline + 1ns) == 0,
                "due and overdue timers must force a nonblocking poll");
        require(timers.expire(deadline).dispatched == 1 && order.empty(), "the rounding timer must only be enqueued by expiry");
        require(scheduler.run_ready(1).resumed == 1 && order == std::vector<size_t>{1}, "the rounding timer must complete through Scheduler");

        const auto far_deadline = TimerQueue::TimePoint::max();
        require_spawned(scheduler.spawn(record_after(timers, far_deadline, 2, order)), "far timer must spawn");
        require(scheduler.run_ready(1).resumed == 1, "far timer must arm");
        require(timers.wait_timeout(base) == INT_MAX, "timeouts beyond epoll's int range must saturate at INT_MAX");
        require(timers.wait_timeout(TimerQueue::TimePoint::min()) == INT_MAX,
                "min-to-max time points must clamp without overflowing their signed duration");
        require(scheduler.cancel_all(), "far timer fixture must hard-cancel");
        require(timers.empty(), "hard frame destruction must unregister the far timer");
        static_cast<void>(scheduler.shutdown());
    }

    TimerQueue timers;
    Scheduler  scheduler;
    require(scheduler.start(), "budget scheduler must start");
    require(timers.start(scheduler), "budget timer queue must start");

    constexpr size_t    timer_count = 129;
    const auto          deadline    = TimerQueue::TimePoint{} + 30s;
    std::vector<size_t> order;
    order.reserve(timer_count);
    for (size_t index = 0; index < timer_count; ++index)
        require_spawned(scheduler.spawn(record_after(timers, deadline, index, order)), "budget timer must spawn");
    require(scheduler.run_ready(timer_count).resumed == timer_count && timers.size() == timer_count && !scheduler.has_ready(),
            "all budget timers must suspend in the timer heap");

    const auto first = timers.expire(deadline, 64);
    require(first.dispatched == 64 && first.has_due && timers.size() == 65 && timers.wait_timeout(deadline) == 0,
            "an expiry budget must leave remaining due work visible as timeout zero");
    require(scheduler.run_ready(64).resumed == 64 && order.size() == 64, "Scheduler's first ready budget must resume 64 timers");

    const auto second = timers.expire(deadline, 64);
    require(second.dispatched == 64 && second.has_due && timers.size() == 1, "the second expiry budget must leave exactly one due timer");
    require(scheduler.run_ready(64).resumed == 64 && order.size() == 128, "Scheduler's second ready budget must resume 64 timers");

    const auto third = timers.expire(deadline, 64);
    require(third.dispatched == 1 && !third.has_due && timers.empty() && scheduler.run_ready(64).resumed == 1,
            "the final expiry pass must drain the remaining timer");
    for (size_t index = 0; index < timer_count; ++index)
        require(order[index] == index, "same-deadline order must remain FIFO across expiry and Scheduler budgets");

    require(timers.invariant_failures() == 0, "normal budget dispatch must not report timer invariants");
    static_cast<void>(scheduler.shutdown());
}

void test_cancellation_and_frame_lifetime()
{
    {
        TimerQueue timers;
        Scheduler  scheduler;
        require(scheduler.start(), "cooperative cancellation scheduler must start");
        require(timers.start(scheduler), "cooperative cancellation timers must start");
        bool caught = false;
        require_spawned(scheduler.spawn(catch_timer_cancellation(timers, TimerQueue::TimePoint{} + 40s, caught)),
                        "cooperative cancellation task must spawn");
        require(scheduler.run_ready(1).resumed == 1 && timers.size() == 1, "cooperative cancellation task must arm");

        const auto cancelled = timers.cancel_all();
        require(cancelled.dispatched == 1 && cancelled.schedule_failures == 0 && scheduler.ready_count() == 1 && !caught && timers.empty(),
                "timer cancellation must enqueue once without inline resume");
        require(scheduler.run_ready(1).resumed == 1 && caught && scheduler.active_count() == 0, "the resumed awaiter must report OperationCancelled");

        require(timers.close(), "cooperative timer queue must close");
        bool closed_caught = false;
        require_spawned(scheduler.spawn(catch_timer_cancellation(timers, TimerQueue::TimePoint{} + 41s, closed_caught)),
                        "closed-queue task must spawn");
        require(scheduler.run_ready(1).resumed == 1 && closed_caught && timers.empty() && !scheduler.has_ready(),
                "a closed queue must reject a new sleep as cancellation without retaining a node");
        static_cast<void>(scheduler.shutdown());
    }

    {
        size_t     destructions = 0;
        TimerQueue timers;
        Scheduler  scheduler;
        require(scheduler.start(), "hard cancellation scheduler must start");
        require(timers.start(scheduler), "hard cancellation timers must start");
        require_spawned(scheduler.spawn(sleeping_probe(timers, TimerQueue::TimePoint{} + 50s, DestructionProbe{destructions})),
                        "hard cancellation task must spawn");
        require(scheduler.run_ready(1).resumed == 1 && timers.size() == 1, "hard cancellation task must arm");
        require(scheduler.cancel_all(), "Scheduler hard cancellation must succeed");
        require(destructions == 1 && timers.empty() && scheduler.active_count() == 0,
                "awaiter destruction must physically unlink an armed timer exactly once");
        require(timers.expire(TimerQueue::TimePoint::max()).dispatched == 0, "an unlinked timer must never complete later as stale heap work");
        static_cast<void>(scheduler.shutdown());
    }

    {
        size_t     destructions = 0;
        bool       completed    = false;
        TimerQueue timers;
        Scheduler  scheduler;
        require(scheduler.start(), "queued-expiry cancellation scheduler must start");
        require(timers.start(scheduler), "queued-expiry cancellation timers must start");
        const auto deadline = TimerQueue::TimePoint{} + 60s;
        require_spawned(scheduler.spawn(sleeping_probe(timers, deadline, DestructionProbe{destructions}, &completed)),
                        "queued-expiry task must spawn");
        require(scheduler.run_ready(1).resumed == 1 && timers.size() == 1, "queued-expiry task must arm");
        require(timers.expire(deadline).dispatched == 1 && scheduler.ready_count() == 1 && timers.empty() && !completed,
                "expired timer must be detached before entering the ready queue");
        require(scheduler.cancel_all(), "queued expired task must be hard-cancellable");
        require(destructions == 1 && !completed && !scheduler.has_ready(), "clearing a queued expiry must destroy its frame without a late resume");
        require(timers.expire(TimerQueue::TimePoint::max()).dispatched == 0, "an already-expired timer must not be completed twice");
        static_cast<void>(scheduler.shutdown());
    }

    {
        size_t    destructions = 0;
        auto      timers       = std::make_unique<TimerQueue>();
        Scheduler scheduler;
        require(scheduler.start(), "early timer destruction scheduler must start");
        require(timers->start(scheduler), "early-destruction timer queue must start");
        require_spawned(scheduler.spawn(sleeping_probe(*timers, TimerQueue::TimePoint{} + 70s, DestructionProbe{destructions})),
                        "early-destruction task must spawn");
        require(scheduler.run_ready(1).resumed == 1 && timers->size() == 1, "early-destruction task must arm");
        timers.reset();
        require(scheduler.cancel_all(), "scheduler must reclaim a frame after its timer queue was detached");
        require(destructions == 1, "detached timer nodes must make reverse lifetime cleanup safe");
        static_cast<void>(scheduler.shutdown());
    }

    size_t automatic_destructions = 0;
    {
        // Declaration order is the production contract: Scheduler is destroyed
        // first, and its awaiter destructors can still unlink from TimerQueue.
        TimerQueue timers;
        Scheduler  scheduler;
        require(scheduler.start(), "automatic lifetime scheduler must start");
        require(timers.start(scheduler), "automatic lifetime timers must start");
        require_spawned(scheduler.spawn(sleeping_probe(timers, TimerQueue::TimePoint{} + 80s, DestructionProbe{automatic_destructions})),
                        "automatic lifetime task must spawn");
        require(scheduler.run_ready(1).resumed == 1 && timers.size() == 1, "automatic lifetime task must arm");
    }
    require(automatic_destructions == 1, "natural Scheduler destruction must reclaim an armed timer frame once");
}

void test_stop_and_structured_shutdown()
{
    {
        std::stop_source external_stop;
        TimerQueue       timers;
        Scheduler        scheduler;
        require(scheduler.start(external_stop.get_token()), "pre-arm stop scheduler must start");
        require(timers.start(scheduler), "pre-arm stop timers must start");

        bool caught = false;
        require_spawned(scheduler.spawn(catch_timer_cancellation(timers, TimerQueue::TimePoint{} + 85s, caught)), "pre-arm stop task must spawn");
        external_stop.request_stop();
        require(scheduler.run_ready(1).resumed == 1 && caught && timers.empty(),
                "a stop observed before await_suspend must cancel without inserting a timer node");
        static_cast<void>(scheduler.shutdown());
    }

    {
        std::stop_source external_stop;
        TimerQueue       timers;
        Scheduler        scheduler;
        require(scheduler.start(external_stop.get_token()), "external-stop scheduler must start");
        require(timers.start(scheduler), "external-stop timers must start");

        bool                  caught = false;
        std::thread::id       resume_thread{};
        const std::thread::id owner_thread = std::this_thread::get_id();
        require_spawned(scheduler.spawn(catch_timer_cancellation(timers, TimerQueue::TimePoint{} + 90s, caught, &resume_thread)),
                        "external-stop timer task must spawn");
        require(scheduler.run_ready(1).resumed == 1 && timers.size() == 1, "external-stop timer task must arm");

        std::jthread requester{[&] { external_stop.request_stop(); }};
        requester.join();
        require(timers.size() == 1 && !scheduler.has_ready() && !caught,
                "a foreign stop request must not mutate the owner-thread timer heap or ready queue");

        require(scheduler.close(), "external-stop scheduler must close on its owner");
        require(timers.close(), "external-stop timer queue must close on its owner");
        require(timers.cancel_all().dispatched == 1, "owner thread must translate external stop into timer cancellation");
        require(scheduler.shutdown(4) == 1 && caught && resume_thread == owner_thread,
                "cancelled timer code must resume and unwind only on the Scheduler owner thread");
    }

    {
        constexpr size_t sleeper_count = 10;
        size_t           destructions  = 0;
        size_t           caught        = 0;
        TimerQueue       timers;
        Scheduler        scheduler;
        require(scheduler.start(), "bounded timer shutdown scheduler must start");
        require(timers.start(scheduler), "bounded timer shutdown queue must start");
        for (size_t index = 0; index < sleeper_count; ++index)
            require_spawned(scheduler.spawn(cancellable_probe(timers, TimerQueue::TimePoint{} + 100s, DestructionProbe{destructions}, caught)),
                            "bounded shutdown sleeper must spawn");
        require(scheduler.run_ready(sleeper_count).resumed == sleeper_count && timers.size() == sleeper_count,
                "bounded shutdown sleepers must all arm");

        require(scheduler.close(), "bounded shutdown scheduler must close");
        require(timers.close(), "bounded shutdown timer queue must close");
        require(timers.cancel_all().dispatched == sleeper_count && timers.empty(),
                "shutdown cancellation must detach every sleeper before frame cleanup");
        require(scheduler.shutdown(3) == 3, "timer shutdown must respect Scheduler's cooperative resume budget");
        require(caught == 3 && destructions == sleeper_count && scheduler.active_count() == 0 && !scheduler.has_ready(),
                "budget exhaustion must hard-destroy every remaining cancelled timer frame exactly once");
    }

    {
        TimerQueue timers;
        Scheduler  scheduler;
        require(scheduler.start(), "nested timer shutdown scheduler must start");
        require(timers.start(scheduler), "nested timer shutdown queue must start");
        bool caught = false;
        require_spawned(scheduler.spawn(parent_catches_child_cancellation(timers, TimerQueue::TimePoint{} + 110s, caught)),
                        "nested timer parent must spawn");
        require(scheduler.run_ready(1).resumed == 1 && scheduler.run_ready(1).resumed == 1 && timers.size() == 1 && scheduler.active_count() == 1,
                "nested child must become the timer waiter while its parent retains ownership");

        require(scheduler.close(), "nested shutdown scheduler must close");
        require(timers.close(), "nested shutdown timers must close");
        require(timers.cancel_all().dispatched == 1, "nested shutdown must enqueue the sleeping child");
        require(scheduler.shutdown(2) == 2 && caught && scheduler.active_count() == 0 && !scheduler.has_ready(),
                "child cancellation must propagate through its scheduled parent continuation");
    }
}

} // namespace

int main()
{
    test_runtime_restart();
    test_sleep_for_and_binding_errors();
    test_deadline_order_and_stable_fifo();
    test_timeout_rounding_and_budgets();
    test_cancellation_and_frame_lifetime();
    test_stop_and_structured_shutdown();
    std::cout << "all timer queue tests passed\n";
    return EXIT_SUCCESS;
}
