#pragma once

#include "DNS_Cache.h"
#include "runtime/UniqueFd.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <sys/eventfd.h>
#include <unistd.h>

struct WorkerContext
{
    size_t                  worker_id{0};
    dns::runtime::UniqueFd  listen_fd;
    dns::runtime::UniqueFd  epoll_fd;
    dns::runtime::UniqueFd  wake_fd;
    Cache::CacheShard      *cache_shard{nullptr};

    void wake() const noexcept
    {
        if (!wake_fd)
            return;
        const uint64_t value = 1;
        ssize_t result;
        do
        {
            result = ::write(wake_fd.get(), &value, sizeof(value));
        } while (result < 0 && errno == EINTR);
    }

    void drain_wakeup() const noexcept
    {
        uint64_t value{0};
        while (::read(wake_fd.get(), &value, sizeof(value)) < 0 && errno == EINTR)
        {
        }
    }
};
