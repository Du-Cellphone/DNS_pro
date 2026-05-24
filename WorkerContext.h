#pragma once

#include <fcntl.h>
#include <unistd.h>
struct WorkerContext
{
    int listen_fd{-1};
    int epoll_fd{-1};

    // mem_pool
    // coroutineScheduler
    // coro_table

    ~WorkerContext()
    {
        if (listen_fd >= 0)
            ::close(listen_fd);
        if (epoll_fd >= 0)
            ::close(epoll_fd);
    }
};