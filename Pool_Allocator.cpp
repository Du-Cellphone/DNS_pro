#include "Pool_Allocator.h"
#include <memory>
#include <mutex>

template <typename T>
PoolAllocator<T>::pointer PoolAllocator<T>::allocate(size_type n)
{
    std::lock_guard<std::mutex> lock(pool_mtx);
    if (pool.empty())
    {
        pointer block = static_cast<pointer>(::operator new(pool_size * sizeof(T)));
        for (size_t i = 0; i < pool_size; ++i)
            pool.push_back(block + i);
    }
    pointer p = pool.back();
    pool.pop_back();
    return p;
}

template <typename T>
void PoolAllocator<T>::deallocate(pointer p, size_type n)
{
    pool.push_back(p);
}

std::allocator<int> a;