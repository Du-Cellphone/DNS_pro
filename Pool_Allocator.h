#pragma once

#include <cstddef>
#include <mutex>
#include <vector>

template <typename T>
class PoolAllocator
{
public:
    using value_type      = T;
    using pointer         = T *;
    using const_pointer   = const T *;
    using reference       = T &;
    using const_reference = const T &;
    using size_type       = std::size_t;
    using difference_type = std::ptrdiff_t;

    pointer allocate(size_type n);
    void    deallocate(pointer p, size_type n);

private:
    std::vector<pointer> pool;
    size_t               pool_size     = 10000;
    size_t               expand_factor = 2;
    std::mutex           pool_mtx;
};