#pragma once

#include <unistd.h>

namespace dns::runtime
{

class UniqueFd final
{
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) noexcept
        : fd_(fd)
    {
    }

    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    UniqueFd(UniqueFd &&other) noexcept
        : fd_(other.release())
    {
    }

    UniqueFd &operator=(UniqueFd &&other) noexcept
    {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] explicit operator bool() const noexcept { return fd_ >= 0; }

    [[nodiscard]] int release() noexcept
    {
        const int result = fd_;
        fd_ = -1;
        return result;
    }

    void reset(int replacement = -1) noexcept
    {
        if (fd_ == replacement)
            return;
        if (fd_ >= 0)
            ::close(fd_);
        fd_ = replacement;
    }

private:
    int fd_{-1};
};

} // namespace dns::runtime
