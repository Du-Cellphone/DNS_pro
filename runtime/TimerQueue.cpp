#include "runtime/TimerQueue.h"

#include <algorithm>
#include <chrono>
#include <climits>
#include <exception>
#include <stdexcept>
#include <utility>

namespace dns::runtime
{

TimerRegistration::~TimerRegistration()
{
    if (owner_ != nullptr)
        owner_->abandon(*this);
}

TimerQueue::~TimerQueue()
{
    // Destruction cannot cooperatively invoke callbacks. Detaching every
    // borrowed registration makes later owner destruction safe in either
    // member order, although normal shutdown completes registrations first.
    while (!heap_.empty())
    {
        TimerRegistration *registration = remove_at(0);
        registration->completion_       = nullptr;
        registration->context_          = nullptr;
    }
}

bool TimerQueue::start(Scheduler &scheduler) noexcept
{
    if (running_ || !heap_.empty() || !scheduler.owns_current_thread())
        return false;

    scheduler_          = &scheduler;
    owner_thread_       = std::this_thread::get_id();
    next_sequence_      = 0;
    invariant_failures_ = 0;
    running_            = true;
    accepting_          = true;
    return true;
}

bool TimerQueue::close() noexcept
{
    if (running_ && !on_owner_thread())
        return false;
    accepting_ = false;
    return true;
}

bool TimerQueue::stop() noexcept
{
    if (running_ && !on_owner_thread())
        return false;
    if (!heap_.empty())
        return false;

    scheduler_    = nullptr;
    owner_thread_ = {};
    running_      = false;
    accepting_    = false;
    return true;
}

TimerQueue::ArmResult TimerQueue::arm(TimerRegistration &registration, TimePoint deadline, CompletionCallback completion, void *context)
{
    if (!running_)
        return ArmResult::NotRunning;
    if (!on_owner_thread())
        return ArmResult::WrongThread;
    if (!accepting_)
        return ArmResult::Closed;
    if (registration.owner_ != nullptr || registration.heap_index_ != TimerRegistration::not_in_heap)
        return ArmResult::AlreadyArmed;
    if (completion == nullptr)
        return ArmResult::InvalidCallback;

    registration.deadline_ = deadline;
    registration.sequence_ = next_sequence_++;

    const size_t index = heap_.size();
    heap_.push_back(&registration);
    registration.owner_      = this;
    registration.heap_index_ = index;
    registration.completion_ = completion;
    registration.context_    = context;
    sift_up(index);
    return ArmResult::Armed;
}

bool TimerQueue::disarm(TimerRegistration &registration) noexcept
{
    if (!running_ || !on_owner_thread() || registration.owner_ != this)
        return false;

    const size_t index = registration.heap_index_;
    if (index >= heap_.size() || heap_[index] != &registration)
    {
        ++invariant_failures_;
        return false;
    }

    static_cast<void>(remove_at(index));
    registration.completion_ = nullptr;
    registration.context_    = nullptr;
    return true;
}

TimerQueue::DispatchResult TimerQueue::expire(TimePoint now, size_t budget) noexcept
{
    DispatchResult result;
    if (!running_ || !on_owner_thread())
        return result;

    while (result.dispatched < budget && !heap_.empty() && heap_.front()->deadline_ <= now)
        complete_front(TimerCompletion::Expired, result);

    result.has_due = !heap_.empty() && heap_.front()->deadline_ <= now;
    return result;
}

TimerQueue::DispatchResult TimerQueue::cancel_all() noexcept
{
    DispatchResult result;
    if (!running_ || !on_owner_thread())
        return result;

    while (!heap_.empty())
        complete_front(TimerCompletion::Cancelled, result);
    return result;
}

int TimerQueue::wait_timeout(TimePoint now) const noexcept
{
    if (heap_.empty())
        return -1;

    const TimePoint deadline = heap_.front()->deadline_;
    if (deadline <= now)
        return 0;

    // Subtracting TimePoint::min() from TimePoint::max() can overflow the
    // signed clock representation before a later INT_MAX clamp. Across the
    // epoch, reject either already-large half first; the remaining subtraction
    // is then bounded to less than twice the maximum epoll interval.
    constexpr auto maximum_wait = std::chrono::duration_cast<Duration>(std::chrono::milliseconds{INT_MAX});
    static_assert(maximum_wait > Duration::zero());
    static_assert(maximum_wait <= Duration::max() / 2);
    const Duration deadline_since_epoch = deadline.time_since_epoch();
    const Duration now_since_epoch      = now.time_since_epoch();
    if (now_since_epoch < Duration::zero() && deadline_since_epoch >= Duration::zero() &&
        (deadline_since_epoch >= maximum_wait || now_since_epoch <= -maximum_wait))
        return INT_MAX;

    const Duration wait_duration = deadline_since_epoch - now_since_epoch;
    if (wait_duration >= maximum_wait)
        return INT_MAX;

    const auto wait = std::chrono::ceil<std::chrono::milliseconds>(wait_duration);
    if (wait.count() >= INT_MAX)
        return INT_MAX;
    return static_cast<int>(wait.count());
}

std::optional<TimerQueue::TimePoint> TimerQueue::next_deadline() const noexcept
{
    if (heap_.empty())
        return std::nullopt;
    return heap_.front()->deadline_;
}

void TimerQueue::abandon(TimerRegistration &registration) noexcept
{
    if (registration.owner_ != this)
        return;
    if (running_ && !on_owner_thread())
        std::terminate();

    size_t index = registration.heap_index_;
    if (index >= heap_.size() || heap_[index] != &registration)
    {
        const auto found = std::find(heap_.begin(), heap_.end(), &registration);
        if (found == heap_.end())
        {
            registration.owner_      = nullptr;
            registration.heap_index_ = TimerRegistration::not_in_heap;
            registration.completion_ = nullptr;
            registration.context_    = nullptr;
            ++invariant_failures_;
            return;
        }
        index = static_cast<size_t>(found - heap_.begin());
        ++invariant_failures_;
    }

    static_cast<void>(remove_at(index));
    registration.completion_ = nullptr;
    registration.context_    = nullptr;
}

void TimerQueue::complete_front(TimerCompletion completion, DispatchResult &result) noexcept
{
    TimerRegistration       *registration = remove_at(0);
    const CompletionCallback callback     = std::exchange(registration->completion_, nullptr);
    void                    *context      = std::exchange(registration->context_, nullptr);
    ++result.dispatched;

    // The callback may make the registration's owner eligible for destruction;
    // do not access registration after this call.
    if (callback == nullptr || !callback(context, completion))
    {
        ++result.schedule_failures;
        ++invariant_failures_;
    }
}

bool TimerQueue::earlier(const TimerRegistration &left, const TimerRegistration &right) noexcept
{
    if (left.deadline_ != right.deadline_)
        return left.deadline_ < right.deadline_;
    return left.sequence_ < right.sequence_;
}

void TimerQueue::swap_nodes(size_t left, size_t right) noexcept
{
    std::swap(heap_[left], heap_[right]);
    heap_[left]->heap_index_  = left;
    heap_[right]->heap_index_ = right;
}

void TimerQueue::sift_up(size_t index) noexcept
{
    while (index != 0)
    {
        const size_t parent = (index - 1) / 2;
        if (!earlier(*heap_[index], *heap_[parent]))
            break;
        swap_nodes(index, parent);
        index = parent;
    }
}

void TimerQueue::sift_down(size_t index) noexcept
{
    while (true)
    {
        const size_t left = index * 2 + 1;
        if (left >= heap_.size())
            return;

        const size_t right    = left + 1;
        size_t       earliest = left;
        if (right < heap_.size() && earlier(*heap_[right], *heap_[left]))
            earliest = right;
        if (!earlier(*heap_[earliest], *heap_[index]))
            return;

        swap_nodes(index, earliest);
        index = earliest;
    }
}

TimerRegistration *TimerQueue::remove_at(size_t index) noexcept
{
    TimerRegistration *removed = heap_[index];
    TimerRegistration *tail    = heap_.back();
    heap_.pop_back();

    if (index < heap_.size())
    {
        heap_[index]      = tail;
        tail->heap_index_ = index;
        if (index != 0 && earlier(*heap_[index], *heap_[(index - 1) / 2]))
            sift_up(index);
        else
            sift_down(index);
    }

    removed->owner_      = nullptr;
    removed->heap_index_ = TimerRegistration::not_in_heap;
    return removed;
}

bool TimerQueue::on_owner_thread() const noexcept
{
    return running_ && owner_thread_ == std::this_thread::get_id();
}

bool SleepAwaiter::complete(void *context, TimerCompletion completion) noexcept
{
    auto                    &awaiter = *static_cast<SleepAwaiter *>(context);
    detail::TaskPromiseBase *task    = std::exchange(awaiter.task_, nullptr);
    awaiter.state_                   = completion == TimerCompletion::Expired ? State::Expired : State::Cancelled;
    return task != nullptr && task->scheduler() != nullptr && task->scheduler()->schedule(*task) == Scheduler::ScheduleResult::Scheduled;
}

void SleepAwaiter::await_resume() const
{
    switch (state_)
    {
        case State::Expired:
            return;
        case State::Cancelled:
            throw OperationCancelled{};
        case State::Failed:
            throw std::logic_error{error_ != nullptr ? error_ : "timer operation failed"};
        case State::Idle:
            throw std::logic_error{"timer operation was never armed"};
        case State::Pending:
            throw std::logic_error{"timer operation resumed before completion"};
    }
    throw std::logic_error{"invalid timer operation state"};
}

} // namespace dns::runtime
