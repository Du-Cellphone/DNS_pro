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

enum class TimerCompletion : uint8_t
{
    Expired,
    Cancelled,
};

// A TimerRegistration is embedded in the object whose lifetime is guarded by
// a deadline. TimerQueue only borrows its address while armed; an armed owner
// must be destroyed or explicitly disarmed on the queue's owner thread.
class TimerRegistration final
{
public:
    TimerRegistration() = default;
    ~TimerRegistration();

    TimerRegistration(const TimerRegistration &)            = delete;
    TimerRegistration &operator=(const TimerRegistration &) = delete;
    TimerRegistration(TimerRegistration &&)                 = delete;
    TimerRegistration &operator=(TimerRegistration &&)      = delete;

    [[nodiscard]] bool armed() const noexcept { return owner_ != nullptr; }

private:
    friend class TimerQueue;

    static constexpr size_t not_in_heap = std::numeric_limits<size_t>::max();

    TimerQueue                           *owner_{nullptr};
    std::chrono::steady_clock::time_point deadline_{};
    uint64_t                              sequence_{0};
    size_t                                heap_index_{not_in_heap};
    bool (*completion_)(void *, TimerCompletion) noexcept {nullptr};
    void *context_{nullptr};
};

// TimerQueue is single-threaded and scheduler-affine after start(). Expiry and
// cancellation detach registrations before invoking their callbacks, so a
// callback may enqueue owner-thread work without leaving a stale heap pointer.
class TimerQueue final
{
public:
    using Clock              = std::chrono::steady_clock;
    using TimePoint          = Clock::time_point;
    using Duration           = Clock::duration;
    using CompletionCallback = bool (*)(void *, TimerCompletion) noexcept;

    enum class ArmResult : uint8_t
    {
        Armed,
        NotRunning,
        Closed,
        WrongThread,
        AlreadyArmed,
        InvalidCallback,
    };

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

    [[nodiscard]] ArmResult arm(TimerRegistration &registration, TimePoint deadline, CompletionCallback completion, void *context);
    [[nodiscard]] bool      disarm(TimerRegistration &registration) noexcept;

    // Due/cancelled registrations are detached and their callbacks invoked;
    // callbacks must enqueue rather than inline-resume coroutine frames.
    [[nodiscard]] DispatchResult expire(TimePoint now, size_t budget = std::numeric_limits<size_t>::max()) noexcept;
    [[nodiscard]] DispatchResult cancel_all() noexcept;

    // epoll_wait-style timeout: -1 for no timer, 0 for an already-due timer,
    // otherwise milliseconds rounded upward and saturated at INT_MAX.
    [[nodiscard]] int                      wait_timeout(TimePoint now) const noexcept;
    [[nodiscard]] std::optional<TimePoint> next_deadline() const noexcept;

    [[nodiscard]] SleepAwaiter sleep_until(TimePoint deadline) noexcept;
    [[nodiscard]] SleepAwaiter sleep_for(Duration delay) noexcept;

    [[nodiscard]] bool   is_bound_to(const Scheduler &scheduler) const noexcept { return running_ && scheduler_ == &scheduler; }
    [[nodiscard]] bool   running() const noexcept { return running_; }
    [[nodiscard]] bool   accepting() const noexcept { return accepting_; }
    [[nodiscard]] bool   empty() const noexcept { return heap_.empty(); }
    [[nodiscard]] size_t size() const noexcept { return heap_.size(); }
    [[nodiscard]] size_t invariant_failures() const noexcept { return invariant_failures_; }

private:
    friend class TimerRegistration;

    void abandon(TimerRegistration &registration) noexcept;
    void complete_front(TimerCompletion completion, DispatchResult &result) noexcept;

    [[nodiscard]] static bool        earlier(const TimerRegistration &left, const TimerRegistration &right) noexcept;
    void                             swap_nodes(size_t left, size_t right) noexcept;
    void                             sift_up(size_t index) noexcept;
    void                             sift_down(size_t index) noexcept;
    [[nodiscard]] TimerRegistration *remove_at(size_t index) noexcept;
    [[nodiscard]] bool               on_owner_thread() const noexcept;

    std::vector<TimerRegistration *> heap_;
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
            state_ = State::Failed;
            error_ = "sleeping coroutine is not bound to a scheduler";
            return false;
        }
        if (task.stop_token().stop_requested())
        {
            state_ = State::Cancelled;
            return false;
        }
        if (!queue_->is_bound_to(*task.scheduler()))
        {
            state_ = State::Failed;
            error_ = "timer queue belongs to another scheduler";
            return false;
        }

        task_  = &task;
        state_ = State::Pending;
        switch (queue_->arm(registration_, deadline_, &SleepAwaiter::complete, this))
        {
            case TimerQueue::ArmResult::Armed:
                return true;
            case TimerQueue::ArmResult::Closed:
                task_  = nullptr;
                state_ = State::Cancelled;
                return false;
            case TimerQueue::ArmResult::NotRunning:
                error_ = "timer queue is not running";
                break;
            case TimerQueue::ArmResult::WrongThread:
                error_ = "timer queue used from a non-owner thread";
                break;
            case TimerQueue::ArmResult::AlreadyArmed:
                error_ = "timer awaiter cannot be armed more than once";
                break;
            case TimerQueue::ArmResult::InvalidCallback:
                error_ = "timer completion callback is invalid";
                break;
        }

        task_  = nullptr;
        state_ = State::Failed;
        return false;
    }

    void await_resume() const;

private:
    enum class State : uint8_t
    {
        Idle,
        Pending,
        Expired,
        Cancelled,
        Failed,
    };

    [[nodiscard]] static bool complete(void *context, TimerCompletion completion) noexcept;

    TimerQueue              *queue_{nullptr};
    TimerQueue::TimePoint    deadline_{};
    TimerRegistration        registration_{};
    detail::TaskPromiseBase *task_{nullptr};
    const char              *error_{nullptr};
    State                    state_{State::Idle};
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
