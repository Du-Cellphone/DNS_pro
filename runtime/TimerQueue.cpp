#include "runtime/TimerQueue.h"

#include <algorithm>
#include <chrono>
#include <climits>
#include <stdexcept>

namespace dns::runtime
{

TimerQueue::~TimerQueue()
{
    // Destruction cannot cooperatively resume tasks. Detaching every borrowed
    // node makes later coroutine-frame destruction safe even if the documented
    // TimerQueue-before-Scheduler member order was not followed.
    while (!heap_.empty())
    {
        detail::TimerNode *node = remove_at(0);
        node->task              = nullptr;
        node->state             = detail::TimerState::Cancelled;
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

TimerQueue::DispatchResult TimerQueue::expire(TimePoint now, size_t budget) noexcept
{
    DispatchResult result;
    if (!running_ || !on_owner_thread())
        return result;

    while (result.dispatched < budget && !heap_.empty() && heap_.front()->deadline <= now)
        complete_front(detail::TimerState::Expired, result);

    result.has_due = !heap_.empty() && heap_.front()->deadline <= now;
    return result;
}

TimerQueue::DispatchResult TimerQueue::cancel_all() noexcept
{
    DispatchResult result;
    if (!running_ || !on_owner_thread())
        return result;

    while (!heap_.empty())
        complete_front(detail::TimerState::Cancelled, result);
    return result;
}

int TimerQueue::wait_timeout(TimePoint now) const noexcept
{
    if (heap_.empty())
        return -1;

    const TimePoint deadline = heap_.front()->deadline;
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
    return heap_.front()->deadline;
}

TimerQueue::ArmResult TimerQueue::arm(detail::TimerNode &node, detail::TaskPromiseBase &task, TimePoint deadline)
{
    if (!running_)
        return ArmResult::NotRunning;
    if (!on_owner_thread())
        return ArmResult::WrongThread;
    if (!accepting_)
        return ArmResult::Closed;
    if (task.scheduler() != scheduler_)
        return ArmResult::WrongScheduler;
    if (node.state != detail::TimerState::Idle || node.owner != nullptr || node.heap_index != detail::TimerNode::not_in_heap)
        return ArmResult::InvalidNode;

    node.deadline = deadline;
    node.sequence = next_sequence_++;
    node.task     = &task;

    const size_t index = heap_.size();
    heap_.push_back(&node);
    node.owner      = this;
    node.heap_index = index;
    node.state      = detail::TimerState::Armed;
    sift_up(index);
    return ArmResult::Armed;
}

void TimerQueue::abandon(detail::TimerNode &node) noexcept
{
    if (node.state != detail::TimerState::Armed || node.owner != this)
        return;

    size_t index = node.heap_index;
    if (index >= heap_.size() || heap_[index] != &node)
    {
        const auto found = std::find(heap_.begin(), heap_.end(), &node);
        if (found == heap_.end())
        {
            node.owner      = nullptr;
            node.task       = nullptr;
            node.heap_index = detail::TimerNode::not_in_heap;
            node.state      = detail::TimerState::Cancelled;
            ++invariant_failures_;
            return;
        }
        index = static_cast<size_t>(found - heap_.begin());
        ++invariant_failures_;
    }

    static_cast<void>(remove_at(index));
    node.task  = nullptr;
    node.state = detail::TimerState::Cancelled;
}

void TimerQueue::complete_front(detail::TimerState completion, DispatchResult &result) noexcept
{
    detail::TimerNode       *node = remove_at(0);
    detail::TaskPromiseBase *task = node->task;
    node->task                    = nullptr;
    node->state                   = completion;
    ++result.dispatched;

    if (scheduler_ == nullptr || task == nullptr || scheduler_->schedule(*task) != Scheduler::ScheduleResult::Scheduled)
    {
        ++result.schedule_failures;
        ++invariant_failures_;
    }
}

bool TimerQueue::earlier(const detail::TimerNode &left, const detail::TimerNode &right) noexcept
{
    if (left.deadline != right.deadline)
        return left.deadline < right.deadline;
    return left.sequence < right.sequence;
}

void TimerQueue::swap_nodes(size_t left, size_t right) noexcept
{
    std::swap(heap_[left], heap_[right]);
    heap_[left]->heap_index  = left;
    heap_[right]->heap_index = right;
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

detail::TimerNode *TimerQueue::remove_at(size_t index) noexcept
{
    detail::TimerNode *removed = heap_[index];
    detail::TimerNode *tail    = heap_.back();
    heap_.pop_back();

    if (index < heap_.size())
    {
        heap_[index]     = tail;
        tail->heap_index = index;
        if (index != 0 && earlier(*heap_[index], *heap_[(index - 1) / 2]))
            sift_up(index);
        else
            sift_down(index);
    }

    removed->owner      = nullptr;
    removed->heap_index = detail::TimerNode::not_in_heap;
    return removed;
}

bool TimerQueue::on_owner_thread() const noexcept
{
    return running_ && owner_thread_ == std::this_thread::get_id();
}

SleepAwaiter::~SleepAwaiter()
{
    // TimerQueue destruction first marks every borrowed node Cancelled and
    // clears owner, so this test must happen before dereferencing an owner.
    if (node_.state == detail::TimerState::Armed && node_.owner != nullptr)
        node_.owner->abandon(node_);
}

void SleepAwaiter::await_resume() const
{
    switch (node_.state)
    {
        case detail::TimerState::Expired:
            return;
        case detail::TimerState::Cancelled:
            throw OperationCancelled{};
        case detail::TimerState::Failed:
            throw std::logic_error{error_ != nullptr ? error_ : "timer operation failed"};
        case detail::TimerState::Idle:
            throw std::logic_error{"timer operation was never armed"};
        case detail::TimerState::Armed:
            throw std::logic_error{"timer operation resumed before completion"};
    }
    throw std::logic_error{"invalid timer operation state"};
}

} // namespace dns::runtime
