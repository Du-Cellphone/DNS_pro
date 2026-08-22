#include "DNS.h"
#include "runtime/UniqueFd.h"

#include <cerrno>
#include <csignal>
#include <iostream>
#include <poll.h>
#include <pthread.h>
#include <sys/signalfd.h>
#include <unistd.h>

int main()
{
    sigset_t stop_signals;
    if (::sigemptyset(&stop_signals) != 0 || ::sigaddset(&stop_signals, SIGINT) != 0 || ::sigaddset(&stop_signals, SIGTERM) != 0 ||
        ::pthread_sigmask(SIG_BLOCK, &stop_signals, nullptr) != 0)
    {
        std::cerr << "failed to configure service stop signals\n";
        return 1;
    }

    dns::runtime::UniqueFd stop_fd{::signalfd(-1, &stop_signals, SFD_CLOEXEC | SFD_NONBLOCK)};
    if (!stop_fd)
    {
        std::cerr << "failed to create service stop signal descriptor\n";
        return 1;
    }

    DNS       dns;
    DNSConfig config;
    config.worker_count            = 15;
    config.runtime_updates_enabled = true;

    if (!dns.init(config))
    {
        std::cerr << "failed to initialize DNS service\n";
        return 1;
    }

    auto started = dns.start();
    if (!started)
    {
        std::cerr << "failed to start DNS service (error " << static_cast<int>(started.error().code) << ")\n";
        return 1;
    }

    bool control_failure{false};
    while (dns.lifecycle_state() == DNSLifecycleState::Active)
    {
        pollfd    signal_event{.fd = stop_fd.get(), .events = POLLIN, .revents = 0};
        const int ready = ::poll(&signal_event, 1, 250);
        if (ready > 0 && (signal_event.revents & POLLIN) != 0)
        {
            signalfd_siginfo signal_info{};
            ssize_t          bytes{0};
            do
            {
                bytes = ::read(stop_fd.get(), &signal_info, sizeof(signal_info));
            } while (bytes < 0 && errno == EINTR);
            control_failure = bytes != static_cast<ssize_t>(sizeof(signal_info));
            dns.request_stop();
            break;
        }
        if (ready > 0 && (signal_event.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        {
            control_failure = true;
            dns.request_stop();
            break;
        }
        if (ready < 0 && errno != EINTR)
        {
            control_failure = true;
            dns.request_stop();
            break;
        }
    }

    const DNSServiceExitResult exited = dns.wait();
    return !control_failure && exited.code == DNSServiceExitCode::ExplicitStop ? 0 : 1;
}
