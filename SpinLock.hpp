#pragma once
#include <atomic>
#include <emmintrin.h>
#include <immintrin.h>


class SpinLock
{
private:
    std::atomic_flag flag = ATOMIC_FLAG_INIT;

public:
    SpinLock()                          = default;
    SpinLock(const SpinLock &)          = delete;
    SpinLock &operator=(const SpinLock) = delete;

    void lock() noexcept
    {
        while (flag.test_and_set(std::memory_order_acquire))
            _mm_pause();
    }
    void unlock() noexcept { flag.clear(std::memory_order_release); }
};