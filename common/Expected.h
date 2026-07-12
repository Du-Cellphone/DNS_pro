#pragma once

#include <cassert>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace dns
{

template <typename Error>
class Unexpected
{
public:
    explicit Unexpected(const Error &error)
        : error_(error)
    {
    }

    explicit Unexpected(Error &&error)
        : error_(std::move(error))
    {
    }

    [[nodiscard]] const Error &error() const & noexcept { return error_; }
    [[nodiscard]] Error       &error() & noexcept { return error_; }
    [[nodiscard]] Error       &&error() && noexcept { return std::move(error_); }

private:
    Error error_;
};

template <typename Error>
Unexpected(Error) -> Unexpected<Error>;

template <typename Error>
Unexpected<std::decay_t<Error>> unexpected(Error &&error)
{
    return Unexpected<std::decay_t<Error>>{std::forward<Error>(error)};
}

template <typename Value, typename Error>
class Expected
{
public:
    Expected(const Value &value)
        : storage_(std::in_place_index<0>, value)
    {
    }

    Expected(Value &&value)
        : storage_(std::in_place_index<0>, std::move(value))
    {
    }

    Expected(const Unexpected<Error> &error)
        : storage_(std::in_place_index<1>, error.error())
    {
    }

    Expected(Unexpected<Error> &&error)
        : storage_(std::in_place_index<1>, std::move(error).error())
    {
    }

    [[nodiscard]] bool has_value() const noexcept { return storage_.index() == 0; }
    explicit operator bool() const noexcept { return has_value(); }

    Value       &value() & { return std::get<0>(storage_); }
    const Value &value() const & { return std::get<0>(storage_); }
    Value       &&value() && { return std::get<0>(std::move(storage_)); }

    Error       &error() & { return std::get<1>(storage_); }
    const Error &error() const & { return std::get<1>(storage_); }
    Error       &&error() && { return std::get<1>(std::move(storage_)); }

    Value       &operator*() & { return value(); }
    const Value &operator*() const & { return value(); }
    Value       &&operator*() && { return std::move(*this).value(); }

    Value       *operator->() { return &value(); }
    const Value *operator->() const { return &value(); }

    bool operator==(const Expected &) const = default;

private:
    std::variant<Value, Error> storage_;
};

template <typename Error>
class Expected<void, Error>
{
public:
    Expected() = default;

    Expected(const Unexpected<Error> &error)
        : error_(error.error())
    {
    }

    Expected(Unexpected<Error> &&error)
        : error_(std::move(error).error())
    {
    }

    [[nodiscard]] bool has_value() const noexcept { return !error_.has_value(); }
    explicit operator bool() const noexcept { return has_value(); }

    void value() const { assert(has_value()); }

    Error       &error() & { return *error_; }
    const Error &error() const & { return *error_; }
    Error       &&error() && { return std::move(*error_); }

private:
    std::optional<Error> error_;
};

} // namespace dns
