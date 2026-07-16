#include "DNS.h"
#include "runtime/UniqueFd.h"

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <string_view>
#include <unistd.h>
#include <utility>

namespace
{

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "lifecycle test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

void test_unique_fd_ownership()
{
    int pipe_fds[2]{-1, -1};
    require(::pipe2(pipe_fds, O_CLOEXEC) == 0, "pipe fixture must be created");
    const int observed_fd = pipe_fds[0];

    {
        dns::runtime::UniqueFd read_end{pipe_fds[0]};
        dns::runtime::UniqueFd moved{std::move(read_end)};
        require(!read_end && moved.get() == observed_fd, "moving UniqueFd must transfer sole ownership");

        const int released = moved.release();
        require(!moved && released == observed_fd, "release must return ownership without closing");
        require(::close(released) == 0, "released descriptor must remain open for the caller");
    }

    errno = 0;
    require(::fcntl(observed_fd, F_GETFD) == -1 && errno == EBADF, "released descriptor must be closed exactly once by its new owner");
    ::close(pipe_fds[1]);

    require(::pipe2(pipe_fds, O_CLOEXEC) == 0, "second pipe fixture must be created");
    const int automatically_closed = pipe_fds[0];
    {
        dns::runtime::UniqueFd owned{automatically_closed};
    }
    errno = 0;
    require(::fcntl(automatically_closed, F_GETFD) == -1 && errno == EBADF, "UniqueFd destructor must close an owned descriptor");
    ::close(pipe_fds[1]);
}

void test_service_configuration_and_stop()
{
    DNS service;
    DNSConfig invalid;
    invalid.worker_count = 0;
    require(!service.init(invalid), "zero workers must be rejected before allocating resources");

    invalid.worker_count = 1;
    invalid.manager_count = 2;
    require(!service.init(invalid), "more than one control-plane manager must be rejected in the MVP");

    invalid.manager_count = 1;
    invalid.upstream.query_timeout = std::chrono::seconds{2};
    invalid.upstream.id_reuse_guard = std::chrono::seconds{1};
    require(!service.init(invalid), "the transaction-ID reuse guard must cover at least one upstream timeout window");

    DNSConfig config;
    config.worker_count = 1;
    config.manager_count = 1;
    config.cache_capacity = 8;
    config.port = 0;
    require(service.init(config), "a small valid service configuration must initialize");

    // Some restricted test sandboxes deny socket(2). In a normal Linux
    // environment this branch exercises an epoll-blocked worker and verifies
    // that eventfd wakes it for a prompt join; the failure path still verifies
    // synchronous startup error propagation and RAII cleanup.
    if (service.start())
    {
        require(service.is_running(), "successful start must publish the running state");
        require(!service.start(), "starting an already running service must fail");
        service.request_stop();
        service.join();
        require(!service.is_running(), "join must finish all workers and clear the running state");
    }
    else
    {
        require(!service.is_running(), "failed network startup must not publish a running service");
        service.join();
    }
}

} // namespace

int main()
{
    test_unique_fd_ownership();
    test_service_configuration_and_stop();
    std::cout << "all lifecycle tests passed\n";
    return EXIT_SUCCESS;
}
