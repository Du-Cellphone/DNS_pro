#pragma once

#include <atomic>
#include <concepts>
#include <coroutine>
#include <cstddef>
#include <exception>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <thread>

namespace dns::runtime
{

template <typename T>
class Task;

class Scheduler;

namespace detail
{

class TaskPromiseBase
{
public:
    TaskPromiseBase() = default;
    TaskPromiseBase(const TaskPromiseBase &) = delete;
    TaskPromiseBase &operator=(const TaskPromiseBase &) = delete;

    [[nodiscard]] std::suspend_always initial_suspend() const noexcept { return {}; }

    class FinalAwaiter
    {
    public:
        [[nodiscard]] bool await_ready() const noexcept { return false; }

        template <typename Promise>
        void await_suspend(std::coroutine_handle<Promise> handle) const noexcept
        {
            static_assert(std::derived_from<Promise, TaskPromiseBase>);
            static_cast<TaskPromiseBase &>(handle.promise()).schedule_continuation();
        }

        void await_resume() const noexcept {}
    };

    [[nodiscard]] FinalAwaiter final_suspend() const noexcept { return {}; }

    void unhandled_exception() noexcept { exception_ = std::current_exception(); }

    [[nodiscard]] Scheduler              *scheduler() const noexcept { return scheduler_; }
    [[nodiscard]] std::stop_token         stop_token() noexcept;
    [[nodiscard]] std::exception_ptr      exception() const noexcept { return exception_; }

private:
    template <typename>
    friend class ::dns::runtime::Task;
    friend class ::dns::runtime::Scheduler;

    void set_handle(std::coroutine_handle<> handle) noexcept { handle_ = handle; }
    [[nodiscard]] bool bind(Scheduler &scheduler, std::stop_token stop_token) noexcept;
    void set_continuation(TaskPromiseBase &continuation) noexcept { continuation_ = &continuation; }
    void clear_continuation() noexcept { continuation_ = nullptr; }
    void schedule_continuation() noexcept;

    Scheduler              *scheduler_{nullptr};
    std::stop_token         stop_token_{};
    std::coroutine_handle<> handle_{};
    std::exception_ptr      exception_{};
    TaskPromiseBase        *continuation_{nullptr};

    TaskPromiseBase *ready_next_{nullptr};
    TaskPromiseBase *root_previous_{nullptr};
    TaskPromiseBase *root_next_{nullptr};
    bool             queued_{false};
    bool             root_{false};
};

template <typename Promise>
concept TaskPromise = std::derived_from<Promise, TaskPromiseBase>;

} // namespace detail

class Scheduler final
{
public:
    // Once started, Scheduler is thread-affine. WrongThread results diagnose
    // serialized misuse; they do not make concurrent method calls safe.
    // Cross-thread shutdown is expressed only through start()'s stop_token.
    // Callbacks registered on a task stop_token may enqueue owner-thread work,
    // but must not destroy scheduler-owned tasks from inside the callback.
    enum class ScheduleResult
    {
        Scheduled,
        Duplicate,
        NotRunning,
        WrongScheduler,
        WrongThread,
        Completed,
    };

    enum class SpawnResult
    {
        Spawned,
        EmptyTask,
        NotAccepting,
        WrongThread,
        InvalidTask,
    };

    struct RunResult
    {
        size_t resumed{0};
        bool   has_ready{false};
    };

    Scheduler() = default;
    ~Scheduler();

    Scheduler(const Scheduler &) = delete;
    Scheduler &operator=(const Scheduler &) = delete;

    [[nodiscard]] bool start(std::stop_token stop_token = {});
    [[nodiscard]] SpawnResult spawn(Task<void> &&task) noexcept;
    [[nodiscard]] ScheduleResult schedule(detail::TaskPromiseBase &task) noexcept;
    [[nodiscard]] RunResult run_ready(size_t budget) noexcept;

    [[nodiscard]] bool close() noexcept;
    [[nodiscard]] size_t shutdown(size_t resume_budget = 1024) noexcept;
    [[nodiscard]] bool cancel_all() noexcept;

    [[nodiscard]] bool   has_ready() const noexcept { return ready_head_ != nullptr; }
    [[nodiscard]] size_t ready_count() const noexcept { return ready_count_; }
    [[nodiscard]] size_t active_count() const noexcept { return active_count_; }
    [[nodiscard]] bool accepting() const noexcept
    {
        return accepting_ && !external_stop_pending_.load(std::memory_order_acquire) && !stop_token_.stop_requested();
    }
    [[nodiscard]] size_t unhandled_root_exceptions() const noexcept { return unhandled_root_exceptions_; }
    [[nodiscard]] size_t invariant_failures() const noexcept { return invariant_failures_; }
    [[nodiscard]] std::exception_ptr last_unhandled_exception() const noexcept { return last_unhandled_exception_; }

private:
    friend class detail::TaskPromiseBase;

    struct ForwardStop
    {
        std::atomic_bool *pending{nullptr};

        void operator()() const noexcept
        {
            if (pending != nullptr)
                pending->store(true, std::memory_order_release);
        }
    };

    void link_root(detail::TaskPromiseBase &task) noexcept;
    void unlink_root(detail::TaskPromiseBase &task) noexcept;
    void finish_root(detail::TaskPromiseBase &task) noexcept;
    void clear_ready() noexcept;
    void cancel_all_now() noexcept;
    void deactivate() noexcept;
    void observe_external_stop() noexcept;
    void record_invariant_failure() noexcept { ++invariant_failures_; }
    [[nodiscard]] bool on_owner_thread() const noexcept;

    detail::TaskPromiseBase *ready_head_{nullptr};
    detail::TaskPromiseBase *ready_tail_{nullptr};
    detail::TaskPromiseBase *root_head_{nullptr};
    size_t                   ready_count_{0};
    size_t                   active_count_{0};
    size_t                   unhandled_root_exceptions_{0};
    size_t                   invariant_failures_{0};
    std::exception_ptr       last_unhandled_exception_{};
    std::stop_source         stop_source_{};
    std::stop_token          stop_token_{};
    std::atomic_bool         external_stop_pending_{false};
    std::optional<std::stop_callback<ForwardStop>> external_stop_callback_{};
    std::thread::id          owner_thread_{};
    bool                     running_{false};
    bool                     accepting_{false};
    bool                     dispatching_{false};
    bool                     cancel_pending_{false};
    bool                     shutdown_pending_{false};
};

class OperationCancelled final : public std::runtime_error
{
public:
    OperationCancelled()
        : std::runtime_error{"coroutine operation cancelled"}
    {
    }
};

namespace this_coro
{

class StopTokenAwaiter
{
public:
    [[nodiscard]] bool await_ready() const noexcept { return false; }

    template <detail::TaskPromise Promise>
    bool await_suspend(std::coroutine_handle<Promise> handle) noexcept
    {
        auto &state = static_cast<detail::TaskPromiseBase &>(handle.promise());
        bound_ = state.scheduler() != nullptr;
        token_ = state.stop_token();
        return false;
    }

    [[nodiscard]] std::stop_token await_resume() const
    {
        if (!bound_)
            throw std::logic_error{"coroutine is not bound to a scheduler"};
        return token_;
    }

private:
    std::stop_token token_{};
    bool            bound_{false};
};

class YieldAwaiter
{
public:
    [[nodiscard]] bool await_ready() const noexcept { return false; }

    template <detail::TaskPromise Promise>
    bool await_suspend(std::coroutine_handle<Promise> handle) noexcept
    {
        auto &state = static_cast<detail::TaskPromiseBase &>(handle.promise());
        if (state.scheduler() == nullptr)
        {
            result_ = Scheduler::ScheduleResult::NotRunning;
            return false;
        }

        result_ = state.scheduler()->schedule(state);
        return result_ == Scheduler::ScheduleResult::Scheduled;
    }

    void await_resume() const
    {
        if (result_ != Scheduler::ScheduleResult::Scheduled)
            throw std::logic_error{"coroutine could not yield to its scheduler"};
    }

private:
    Scheduler::ScheduleResult result_{Scheduler::ScheduleResult::NotRunning};
};

class CancellationPointAwaiter
{
public:
    [[nodiscard]] bool await_ready() const noexcept { return false; }

    template <detail::TaskPromise Promise>
    bool await_suspend(std::coroutine_handle<Promise> handle) noexcept
    {
        auto &state = static_cast<detail::TaskPromiseBase &>(handle.promise());
        bound_ = state.scheduler() != nullptr;
        cancelled_ = state.stop_token().stop_requested();
        return false;
    }

    void await_resume() const
    {
        if (!bound_)
            throw std::logic_error{"coroutine is not bound to a scheduler"};
        if (cancelled_)
            throw OperationCancelled{};
    }

private:
    bool bound_{false};
    bool cancelled_{false};
};

[[nodiscard]] inline StopTokenAwaiter stop_token() noexcept { return {}; }
[[nodiscard]] inline YieldAwaiter yield() noexcept { return {}; }
[[nodiscard]] inline CancellationPointAwaiter cancellation_point() noexcept { return {}; }

} // namespace this_coro

} // namespace dns::runtime
