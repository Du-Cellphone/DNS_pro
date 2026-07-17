#include "DNS.h"
#include "runtime/UniqueFd.h"

#include <cerrno>
#include <barrier>
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <string_view>
#include <thread>
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
    DNS  not_initialized;
    auto not_running = not_initialized.replace_blocked_domains({"example.com"});
    require(!not_running && not_running.error().code == dns::server::FilterUpdateErrorCode::ServiceNotRunning,
            "reload before initialization must fail without queuing work");

    DNS       invalid_rules_service;
    DNSConfig invalid_rules;
    invalid_rules.blocked_domains = {"*.example"};
    require(!invalid_rules_service.init(invalid_rules), "unsupported wildcard rules must fail before a filter snapshot is published");

    DNS       service;
    DNSConfig invalid;
    invalid.worker_count = 0;
    require(!service.init(invalid), "zero workers must be rejected before allocating resources");

    invalid.worker_count  = 1;
    invalid.manager_count = 2;
    require(!service.init(invalid), "more than one control-plane manager must be rejected in the MVP");

    invalid.manager_count           = 1;
    invalid.upstream.query_timeout  = std::chrono::seconds{2};
    invalid.upstream.id_reuse_guard = std::chrono::seconds{1};
    require(!service.init(invalid), "the transaction-ID reuse guard must cover at least one upstream timeout window");

    DNSConfig config;
    config.worker_count   = 1;
    config.manager_count  = 1;
    config.cache_capacity = 8;
    config.port           = 0;
    require(service.init(config), "a small valid service configuration must initialize");
    require(service.filter_version() == std::optional{dns::server::FilterVersion{1, 0}},
            "initialization must publish the compiled generation-one snapshot");

    auto initialized_reload = service.replace_blocked_domains({"example.com"});
    require(!initialized_reload && initialized_reload.error().code == dns::server::FilterUpdateErrorCode::ServiceNotRunning,
            "reload requires a running manager rather than building on the caller thread");

    // Some restricted test sandboxes deny socket(2). In a normal Linux
    // environment this branch exercises an epoll-blocked worker and verifies
    // that eventfd wakes it for a prompt join; the failure path still verifies
    // synchronous startup error propagation and RAII cleanup.
    if (service.start())
    {
        require(service.is_running(), "successful start must publish the running state");
        require(!service.start(), "starting an already running service must fail");

        std::barrier                                   shutdown_gate{3};
        std::optional<dns::server::FilterUpdateResult> raced_reload;
        std::jthread                                   reloader{[&]
                              {
                                  shutdown_gate.arrive_and_wait();
                                  raced_reload.emplace(service.replace_blocked_domains({"race.example"}));
                              }};
        std::jthread                                   stopper{[&]
                             {
                                 shutdown_gate.arrive_and_wait();
                                 service.request_stop();
                             }};
        shutdown_gate.arrive_and_wait();
        reloader.join();
        stopper.join();
        require(raced_reload.has_value(), "a reload racing shutdown must always complete");
        require(*raced_reload || raced_reload->error().code == dns::server::FilterUpdateErrorCode::ShuttingDown,
                "a reload racing shutdown must either commit first or report shutdown");

        std::barrier join_gate{3};
        std::jthread first_joiner{[&]
                                  {
                                      join_gate.arrive_and_wait();
                                      service.join();
                                  }};
        std::jthread second_joiner{[&]
                                   {
                                       join_gate.arrive_and_wait();
                                       service.join();
                                   }};
        join_gate.arrive_and_wait();
        first_joiner.join();
        second_joiner.join();
        require(!service.is_running(), "join must finish all workers and clear the running state");

        auto stopped_reload = service.replace_blocked_domains({"example.com"});
        require(!stopped_reload && stopped_reload.error().code == dns::server::FilterUpdateErrorCode::ShuttingDown,
                "reload after shutdown must complete immediately with a shutdown error");
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
