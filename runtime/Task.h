#pragma once

#include "runtime/Scheduler.h"

#include <coroutine>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace dns::runtime
{

template <typename T>
class [[nodiscard]] Task final
{
    static_assert(!std::is_void_v<T>);
    static_assert(!std::is_reference_v<T>);

public:
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;

    Task() = default;

    Task(Task &&other) noexcept
        : handle_(std::exchange(other.handle_, {}))
    {
    }

    Task &operator=(Task &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            handle_ = std::exchange(other.handle_, {});
        }
        return *this;
    }

    ~Task() { reset(); }

    Task(const Task &) = delete;
    Task &operator=(const Task &) = delete;

    [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(handle_); }

    class Awaiter final
    {
    public:
        explicit Awaiter(handle_type handle) noexcept
            : handle_(handle)
        {
        }

        Awaiter(Awaiter &&other) noexcept
            : handle_(std::exchange(other.handle_, {}))
            , error_(other.error_)
        {
        }

        Awaiter(const Awaiter &) = delete;
        Awaiter &operator=(const Awaiter &) = delete;
        Awaiter &operator=(Awaiter &&) = delete;

        ~Awaiter()
        {
            if (handle_)
                handle_.destroy();
        }

        [[nodiscard]] bool await_ready() const noexcept { return !handle_ || handle_.done(); }

        template <detail::TaskPromise ParentPromise>
        bool await_suspend(std::coroutine_handle<ParentPromise> parent) noexcept
        {
            if (!handle_)
            {
                error_ = "cannot await an empty task";
                return false;
            }

            auto &parent_state = static_cast<detail::TaskPromiseBase &>(parent.promise());
            auto &child_state = static_cast<detail::TaskPromiseBase &>(handle_.promise());
            Scheduler *scheduler = parent_state.scheduler();
            if (scheduler == nullptr)
            {
                error_ = "parent task is not bound to a scheduler";
                return false;
            }
            if (!child_state.bind(*scheduler, parent_state.stop_token()))
            {
                error_ = "child task belongs to another scheduler";
                return false;
            }

            child_state.set_continuation(parent_state);
            const auto result = scheduler->schedule(child_state);
            if (result != Scheduler::ScheduleResult::Scheduled)
            {
                child_state.clear_continuation();
                error_ = "child task could not be scheduled";
                return false;
            }
            return true;
        }

        T await_resume()
        {
            if (error_ != nullptr)
                throw std::logic_error{error_};
            if (!handle_)
                throw std::logic_error{"cannot resume an empty task"};
            if (!handle_.done())
                throw std::logic_error{"child task resumed before completion"};
            if (auto exception = handle_.promise().exception())
                std::rethrow_exception(exception);
            return handle_.promise().take_result();
        }

    private:
        handle_type  handle_{};
        const char  *error_{nullptr};
    };

    [[nodiscard]] Awaiter operator co_await() && noexcept { return Awaiter{release()}; }
    Awaiter operator co_await() & = delete;

    struct promise_type final : detail::TaskPromiseBase
    {
        [[nodiscard]] Task get_return_object() noexcept
        {
            auto handle = handle_type::from_promise(*this);
            set_handle(handle);
            return Task{handle};
        }

        template <typename U>
        requires std::constructible_from<T, U &&>
        void return_value(U &&value) noexcept(std::is_nothrow_constructible_v<T, U &&>)
        {
            result_.emplace(std::forward<U>(value));
        }

        [[nodiscard]] T take_result()
        {
            if (!result_)
                throw std::logic_error{"task completed without a result"};
            return std::move(*result_);
        }

    private:
        std::optional<T> result_{};
    };

private:
    friend class Scheduler;

    explicit Task(handle_type handle) noexcept
        : handle_(handle)
    {
    }

    [[nodiscard]] handle_type release() noexcept { return std::exchange(handle_, {}); }

    void reset() noexcept
    {
        if (handle_)
            handle_.destroy();
        handle_ = {};
    }

    handle_type handle_{};
};

template <>
class [[nodiscard]] Task<void> final
{
public:
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;

    Task() = default;

    Task(Task &&other) noexcept
        : handle_(std::exchange(other.handle_, {}))
    {
    }

    Task &operator=(Task &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            handle_ = std::exchange(other.handle_, {});
        }
        return *this;
    }

    ~Task() { reset(); }

    Task(const Task &) = delete;
    Task &operator=(const Task &) = delete;

    [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(handle_); }

    class Awaiter final
    {
    public:
        explicit Awaiter(handle_type handle) noexcept
            : handle_(handle)
        {
        }

        Awaiter(Awaiter &&other) noexcept
            : handle_(std::exchange(other.handle_, {}))
            , error_(other.error_)
        {
        }

        Awaiter(const Awaiter &) = delete;
        Awaiter &operator=(const Awaiter &) = delete;
        Awaiter &operator=(Awaiter &&) = delete;

        ~Awaiter()
        {
            if (handle_)
                handle_.destroy();
        }

        [[nodiscard]] bool await_ready() const noexcept { return !handle_ || handle_.done(); }

        template <detail::TaskPromise ParentPromise>
        bool await_suspend(std::coroutine_handle<ParentPromise> parent) noexcept
        {
            if (!handle_)
            {
                error_ = "cannot await an empty task";
                return false;
            }

            auto &parent_state = static_cast<detail::TaskPromiseBase &>(parent.promise());
            auto &child_state = static_cast<detail::TaskPromiseBase &>(handle_.promise());
            Scheduler *scheduler = parent_state.scheduler();
            if (scheduler == nullptr)
            {
                error_ = "parent task is not bound to a scheduler";
                return false;
            }
            if (!child_state.bind(*scheduler, parent_state.stop_token()))
            {
                error_ = "child task belongs to another scheduler";
                return false;
            }

            child_state.set_continuation(parent_state);
            const auto result = scheduler->schedule(child_state);
            if (result != Scheduler::ScheduleResult::Scheduled)
            {
                child_state.clear_continuation();
                error_ = "child task could not be scheduled";
                return false;
            }
            return true;
        }

        void await_resume()
        {
            if (error_ != nullptr)
                throw std::logic_error{error_};
            if (!handle_)
                throw std::logic_error{"cannot resume an empty task"};
            if (!handle_.done())
                throw std::logic_error{"child task resumed before completion"};
            if (auto exception = handle_.promise().exception())
                std::rethrow_exception(exception);
        }

    private:
        handle_type handle_{};
        const char *error_{nullptr};
    };

    [[nodiscard]] Awaiter operator co_await() && noexcept { return Awaiter{release()}; }
    Awaiter operator co_await() & = delete;

    struct promise_type final : detail::TaskPromiseBase
    {
        [[nodiscard]] Task get_return_object() noexcept
        {
            auto handle = handle_type::from_promise(*this);
            set_handle(handle);
            return Task{handle};
        }

        void return_void() const noexcept {}
    };

private:
    friend class Scheduler;

    explicit Task(handle_type handle) noexcept
        : handle_(handle)
    {
    }

    [[nodiscard]] handle_type release() noexcept { return std::exchange(handle_, {}); }

    void reset() noexcept
    {
        if (handle_)
            handle_.destroy();
        handle_ = {};
    }

    handle_type handle_{};
};

} // namespace dns::runtime
