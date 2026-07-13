#include "runtime/Scheduler.h"

#include "runtime/Task.h"

#include <utility>

namespace dns::runtime
{

bool detail::TaskPromiseBase::bind(Scheduler &scheduler, std::stop_token stop_token) noexcept
{
    if (scheduler_ != nullptr && scheduler_ != &scheduler)
        return false;
    scheduler_ = &scheduler;
    stop_token_ = stop_token;
    return true;
}

std::stop_token detail::TaskPromiseBase::stop_token() noexcept
{
    if (scheduler_ != nullptr)
        scheduler_->observe_external_stop();
    return stop_token_;
}

void detail::TaskPromiseBase::schedule_continuation() noexcept
{
    if (continuation_ == nullptr)
        return;
    if (scheduler_ == nullptr || scheduler_->schedule(*continuation_) != Scheduler::ScheduleResult::Scheduled)
    {
        if (scheduler_ != nullptr)
            scheduler_->record_invariant_failure();
    }
}

Scheduler::~Scheduler()
{
    static_cast<void>(stop_source_.request_stop());
    accepting_ = false;
    cancel_all_now();
    deactivate();
}

bool Scheduler::start(std::stop_token stop_token)
{
    if (running_ || ready_head_ != nullptr || root_head_ != nullptr)
        return false;

    external_stop_callback_.reset();
    stop_source_ = std::stop_source{};
    external_stop_pending_.store(false, std::memory_order_relaxed);
    external_stop_callback_.emplace(stop_token, ForwardStop{&external_stop_pending_});
    stop_token_ = stop_source_.get_token();
    owner_thread_ = std::this_thread::get_id();
    running_ = true;
    observe_external_stop();
    accepting_ = !stop_token_.stop_requested();
    return true;
}

Scheduler::SpawnResult Scheduler::spawn(Task<void> &&task) noexcept
{
    if (!task.handle_)
        return SpawnResult::EmptyTask;
    if (running_ && !on_owner_thread())
        return SpawnResult::WrongThread;
    if (!running_)
        return SpawnResult::NotAccepting;
    observe_external_stop();
    if (!accepting_ || stop_token_.stop_requested())
        return SpawnResult::NotAccepting;

    auto &state = static_cast<detail::TaskPromiseBase &>(task.handle_.promise());
    if (!state.bind(*this, stop_token_) || state.root_ || state.queued_ || state.handle_.done())
        return SpawnResult::InvalidTask;

    link_root(state);
    const auto scheduled = schedule(state);
    if (scheduled != ScheduleResult::Scheduled)
    {
        unlink_root(state);
        return scheduled == ScheduleResult::WrongThread ? SpawnResult::WrongThread : SpawnResult::InvalidTask;
    }

    static_cast<void>(task.release());
    return SpawnResult::Spawned;
}

Scheduler::ScheduleResult Scheduler::schedule(detail::TaskPromiseBase &task) noexcept
{
    if (!running_)
        return ScheduleResult::NotRunning;
    if (!on_owner_thread())
        return ScheduleResult::WrongThread;
    if (task.scheduler_ != this)
        return ScheduleResult::WrongScheduler;
    if (!task.handle_ || task.handle_.done())
        return ScheduleResult::Completed;
    if (task.queued_)
        return ScheduleResult::Duplicate;

    task.ready_next_ = nullptr;
    task.queued_ = true;
    if (ready_tail_ != nullptr)
        ready_tail_->ready_next_ = &task;
    else
        ready_head_ = &task;
    ready_tail_ = &task;
    ++ready_count_;
    return ScheduleResult::Scheduled;
}

Scheduler::RunResult Scheduler::run_ready(size_t budget) noexcept
{
    if (!running_ || !on_owner_thread())
        return RunResult{0, has_ready()};
    if (dispatching_)
    {
        record_invariant_failure();
        return RunResult{0, has_ready()};
    }
    observe_external_stop();

    size_t resumed = 0;
    while (resumed < budget && ready_head_ != nullptr)
    {
        detail::TaskPromiseBase *task = ready_head_;
        ready_head_ = task->ready_next_;
        if (ready_head_ == nullptr)
            ready_tail_ = nullptr;
        task->ready_next_ = nullptr;
        task->queued_ = false;
        --ready_count_;

        const bool root = task->root_;
        auto       handle = task->handle_;
        dispatching_ = true;
        handle.resume();
        dispatching_ = false;
        ++resumed;

        // A non-root frame is owned by an awaiter in its suspended parent.
        // Only roots are safe for the Scheduler to inspect and destroy here.
        if (root && handle.done())
            finish_root(*task);

        if (cancel_pending_)
        {
            const bool deactivate_scheduler = shutdown_pending_;
            cancel_pending_ = false;
            shutdown_pending_ = false;
            cancel_all_now();
            if (deactivate_scheduler)
                deactivate();
            break;
        }
    }

    return RunResult{resumed, has_ready()};
}

bool Scheduler::close() noexcept
{
    if (running_ && !on_owner_thread())
        return false;
    accepting_ = false;
    return true;
}

size_t Scheduler::shutdown(size_t resume_budget) noexcept
{
    if (running_ && !on_owner_thread())
        return 0;
    static_cast<void>(stop_source_.request_stop());
    accepting_ = false;
    if (dispatching_)
    {
        cancel_pending_ = true;
        shutdown_pending_ = true;
        return 0;
    }

    size_t resumed = 0;
    while (running_ && resumed < resume_budget && has_ready())
    {
        const auto result = run_ready(resume_budget - resumed);
        if (result.resumed == 0)
            break;
        resumed += result.resumed;
    }

    if (running_)
    {
        cancel_all_now();
        deactivate();
    }
    return resumed;
}

bool Scheduler::cancel_all() noexcept
{
    if (running_ && !on_owner_thread())
        return false;
    static_cast<void>(stop_source_.request_stop());
    accepting_ = false;
    if (dispatching_)
    {
        cancel_pending_ = true;
        return true;
    }

    cancel_all_now();
    return true;
}

void Scheduler::cancel_all_now() noexcept
{
    clear_ready();

    while (root_head_ != nullptr)
    {
        detail::TaskPromiseBase *root = root_head_;
        unlink_root(*root);
        auto handle = root->handle_;
        root->handle_ = {};
        handle.destroy();
    }
}

void Scheduler::deactivate() noexcept
{
    running_ = false;
    accepting_ = false;
    dispatching_ = false;
    cancel_pending_ = false;
    shutdown_pending_ = false;
    owner_thread_ = {};
    external_stop_callback_.reset();
    external_stop_pending_.store(false, std::memory_order_relaxed);
    stop_token_ = {};
}

void Scheduler::observe_external_stop() noexcept
{
    if (external_stop_pending_.load(std::memory_order_acquire))
    {
        static_cast<void>(stop_source_.request_stop());
        accepting_ = false;
    }
}

void Scheduler::link_root(detail::TaskPromiseBase &task) noexcept
{
    task.root_ = true;
    task.root_previous_ = nullptr;
    task.root_next_ = root_head_;
    if (root_head_ != nullptr)
        root_head_->root_previous_ = &task;
    root_head_ = &task;
    ++active_count_;
}

void Scheduler::unlink_root(detail::TaskPromiseBase &task) noexcept
{
    if (!task.root_)
        return;
    if (task.root_previous_ != nullptr)
        task.root_previous_->root_next_ = task.root_next_;
    else
        root_head_ = task.root_next_;
    if (task.root_next_ != nullptr)
        task.root_next_->root_previous_ = task.root_previous_;
    task.root_previous_ = nullptr;
    task.root_next_ = nullptr;
    task.root_ = false;
    --active_count_;
}

void Scheduler::finish_root(detail::TaskPromiseBase &task) noexcept
{
    if (auto exception = task.exception_)
    {
        ++unhandled_root_exceptions_;
        last_unhandled_exception_ = std::move(exception);
    }

    auto handle = task.handle_;
    unlink_root(task);
    task.handle_ = {};
    handle.destroy();
}

void Scheduler::clear_ready() noexcept
{
    while (ready_head_ != nullptr)
    {
        detail::TaskPromiseBase *task = ready_head_;
        ready_head_ = task->ready_next_;
        task->ready_next_ = nullptr;
        task->queued_ = false;
    }
    ready_tail_ = nullptr;
    ready_count_ = 0;
}

bool Scheduler::on_owner_thread() const noexcept
{
    return running_ && owner_thread_ == std::this_thread::get_id();
}

} // namespace dns::runtime
