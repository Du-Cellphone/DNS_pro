#pragma once

#include "runtime/Scheduler.h"

#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <thread>
#include <vector>

namespace dns::runtime
{

class TimerQueue;
class SleepAwaiter;

namespace detail
{

enum class TimerState : uint8_t
{
    Idle,
    Armed,
    Expired,
    Cancelled,
    Failed,
};

struct TimerNode final
{
    static constexpr size_t not_in_heap = std::numeric_limits<size_t>::max();

    TimerQueue                           *owner{nullptr};
    TaskPromiseBase                      *task{nullptr};
    std::chrono::steady_clock::time_point deadline{};
    uint64_t                              sequence{0};
    size_t                                heap_index{not_in_heap};
    TimerState                            state{TimerState::Idle};
};

} // namespace detail

// TimerQueue is single-threaded and scheduler-affine after start(). It only
// borrows TimerNode objects embedded in suspended coroutine frames; Scheduler
// remains the sole owner of those frames.
class TimerQueue final
{
public:
    using Clock     = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration  = Clock::duration;

    struct DispatchResult
    {
        size_t dispatched{0};
        size_t schedule_failures{0};
        bool   has_due{false};
    };

    TimerQueue() = default;
    ~TimerQueue();

    TimerQueue(const TimerQueue &)            = delete;
    TimerQueue &operator=(const TimerQueue &) = delete;
    TimerQueue(TimerQueue &&)                 = delete;
    TimerQueue &operator=(TimerQueue &&)      = delete;

    [[nodiscard]] bool start(Scheduler &scheduler) noexcept;
    [[nodiscard]] bool close() noexcept;
    // stop() unbinds an already-empty queue so both runtime components can be
    // started again. Call close()/cancel_all() and reclaim frames first.
    [[nodiscard]] bool stop() noexcept;

    // Due/cancelled operations are enqueued on Scheduler and never resumed
    // inline. The budget counts timers removed from the heap, including a
    // timer whose Scheduler enqueue reports an invariant failure.
    [[nodiscard]] DispatchResult expire(TimePoint now, size_t budget = std::numeric_limits<size_t>::max()) noexcept;
    [[nodiscard]] DispatchResult cancel_all() noexcept;

    // epoll_wait-style timeout: -1 for no timer, 0 for an already-due timer,
    // otherwise milliseconds rounded upward and saturated at INT_MAX.
    [[nodiscard]] int                      wait_timeout(TimePoint now) const noexcept;
    [[nodiscard]] std::optional<TimePoint> next_deadline() const noexcept;

    [[nodiscard]] SleepAwaiter sleep_until(TimePoint deadline) noexcept;
    [[nodiscard]] SleepAwaiter sleep_for(Duration delay) noexcept;

    [[nodiscard]] bool   running() const noexcept { return running_; }
    [[nodiscard]] bool   accepting() const noexcept { return accepting_; }
    [[nodiscard]] bool   empty() const noexcept { return heap_.empty(); }
    [[nodiscard]] size_t size() const noexcept { return heap_.size(); }
    [[nodiscard]] size_t invariant_failures() const noexcept { return invariant_failures_; }

private:
    friend class SleepAwaiter;

    enum class ArmResult : uint8_t
    {
        Armed,
        NotRunning,
        Closed,
        WrongThread,
        WrongScheduler,
        InvalidNode,
    };

    [[nodiscard]] ArmResult arm(detail::TimerNode &node, detail::TaskPromiseBase &task, TimePoint deadline);
    void                    abandon(detail::TimerNode &node) noexcept;
    void                    complete_front(detail::TimerState completion, DispatchResult &result) noexcept;

    [[nodiscard]] static bool        earlier(const detail::TimerNode &left, const detail::TimerNode &right) noexcept;
    void                             swap_nodes(size_t left, size_t right) noexcept;
    void                             sift_up(size_t index) noexcept;
    void                             sift_down(size_t index) noexcept;
    [[nodiscard]] detail::TimerNode *remove_at(size_t index) noexcept;
    [[nodiscard]] bool               on_owner_thread() const noexcept;

    std::vector<detail::TimerNode *> heap_;
    Scheduler                       *scheduler_{nullptr};
    std::thread::id                  owner_thread_{};
    uint64_t                         next_sequence_{0};
    size_t                           invariant_failures_{0};
    bool                             running_{false};
    bool                             accepting_{false};
};

class SleepAwaiter final
{
public:
    SleepAwaiter(TimerQueue &queue, TimerQueue::TimePoint deadline) noexcept
        : queue_(&queue)
        , deadline_(deadline)
    {
    }

    ~SleepAwaiter();

    SleepAwaiter(const SleepAwaiter &)            = delete;
    SleepAwaiter &operator=(const SleepAwaiter &) = delete;
    SleepAwaiter(SleepAwaiter &&)                 = delete;
    SleepAwaiter &operator=(SleepAwaiter &&)      = delete;

    [[nodiscard]] bool await_ready() const noexcept { return false; }

    template <detail::TaskPromise Promise>
    bool await_suspend(std::coroutine_handle<Promise> handle)
    {
        auto &task = static_cast<detail::TaskPromiseBase &>(handle.promise());
        if (task.scheduler() == nullptr)
        {
            node_.state = detail::TimerState::Failed;
            error_      = "sleeping coroutine is not bound to a scheduler";
            return false;
        }
        if (task.stop_token().stop_requested())
        {
            node_.state = detail::TimerState::Cancelled;
            return false;
        }

        switch (queue_->arm(node_, task, deadline_))
        {
            case TimerQueue::ArmResult::Armed:
                return true;
            case TimerQueue::ArmResult::Closed:
                node_.state = detail::TimerState::Cancelled;
                return false;
            case TimerQueue::ArmResult::NotRunning:
                error_ = "timer queue is not running";
                break;
            case TimerQueue::ArmResult::WrongThread:
                error_ = "timer queue used from a non-owner thread";
                break;
            case TimerQueue::ArmResult::WrongScheduler:
                error_ = "timer queue belongs to another scheduler";
                break;
            case TimerQueue::ArmResult::InvalidNode:
                error_ = "timer awaiter cannot be armed more than once";
                break;
        }

        if (node_.state == detail::TimerState::Idle)
            node_.state = detail::TimerState::Failed;
        return false;
    }

    void await_resume() const;

private:
    TimerQueue           *queue_{nullptr};
    TimerQueue::TimePoint deadline_{};
    detail::TimerNode     node_{};
    const char           *error_{nullptr};
};

inline SleepAwaiter TimerQueue::sleep_until(TimePoint deadline) noexcept
{
    return SleepAwaiter{*this, deadline};
}

inline SleepAwaiter TimerQueue::sleep_for(Duration delay) noexcept
{
    const TimePoint now = Clock::now();
    if (delay <= Duration::zero())
        return SleepAwaiter{*this, now};

    const Duration since_epoch = now.time_since_epoch();
    if (since_epoch > Duration::zero() && delay > Duration::max() - since_epoch)
        return SleepAwaiter{*this, TimePoint::max()};
    return SleepAwaiter{*this, TimePoint{since_epoch + delay}};
}

} // namespace dns::runtime
