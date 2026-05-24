#include "DNS.h"
#include "DNS_Cache.h"
#include "WorkerContext.h"
#include <cerrno>
#include <cstring>
#include <memory>

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

bool DNS::init(size_t worker_thread_cnt, size_t manager_thread_cnt)
{
    if (worker_thread_cnt + manager_thread_cnt <= 1)
        return false;

    cache = std::make_unique<Cache::DNS_Cache>(worker_thread_cnt);
    active_context.store(std::make_shared<FilterContext>());

    worker_count  = worker_thread_cnt;
    manager_count = manager_thread_cnt;

    port = 5353;

    return true;
}

void DNS::start()
{
    // 1个管理线程，剩余为工作线程
    for (int i = 0; i < worker_count; ++i)
        worker_threads.emplace_back([this]() { worker(); });

    for (int i = 0; i < manager_count; ++i)
        manager_threads.emplace_back([this]() { manager(); });
}

void DNS::worker()
{
    WorkerContext ctx;
    if (!init_network_env(ctx, port))
        return;

    std::cout << "[Worker] 线程网络句柄初始化完毕，无锁监听中..." << std::endl;

    struct epoll_event events[64];
    uint8_t            buffer[1024];

    while (true)
    {
        int nfds = ::epoll_wait(ctx.epoll_fd, events, 64, -1);

        for (int i = 0; i < nfds; ++i)
        {
            if (events[i].data.fd != ctx.listen_fd)
            {
                // 待办：
                // 1. timerfd用来确保协程不会永远挂起
                // 2. 支持TCP
            }

            while (true)
            {
                struct sockaddr_in client_addr{};
                socklen_t          client_len = sizeof(client_addr);

                ssize_t bytes_recvd = ::recvfrom(ctx.listen_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_len);

                if (bytes_recvd < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        break;
                    }
                    // 发生真实网络错误
                    break;
                }
            }
        }
    }
}

void DNS::manager() {}

bool DNS::init_network_env(WorkerContext &ctx, uint16_t port)
{
    ctx.listen_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (ctx.listen_fd < 0)
    {
        std::cerr << "failed to create Socket " << strerror(errno) << std::endl;
        return false;
    }

    int opt{1};
    if (::setsockopt(ctx.listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
    {
        std::cerr << "failed to set SO_REUSEPORT " << strerror(errno) << std::endl;
        return false;
    }

    struct sockaddr_in addr{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (::bind(ctx.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        std::cerr << "failed to bind port " << strerror(errno) << std::endl;
        return false;
    }

    ctx.epoll_fd = ::epoll_create1(0);
    if (ctx.epoll_fd < 0)
    {
        std::cerr << "failed to create epoll " << std::endl;
        return false;
    }

    struct epoll_event ev{};
    ev.events  = EPOLLIN | EPOLLET;
    ev.data.fd = ctx.listen_fd;

    if (::epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, ctx.listen_fd, &ev) < 0)
    {
        std::cerr << "failed to register epoll " << std::endl;
        return false;
    }

    return true;
};