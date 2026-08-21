#pragma once

#include "runtime/UniqueFd.h"

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <poll.h>
#include <string_view>
#include <sys/socket.h>

#ifndef DNS_PRO_REQUIRE_SOCKET_TESTS
#define DNS_PRO_REQUIRE_SOCKET_TESTS 0
#endif

namespace dns::test
{

inline constexpr int kSocketTestSkipReturnCode = 77;

struct SocketCapability
{
    bool             available{false};
    bool             skippable{false};
    int              error_number{0};
    std::string_view operation;
};

[[nodiscard]] inline bool is_unavailable_socket_error(int error_number) noexcept
{
    switch (error_number)
    {
        case EPERM:
        case EACCES:
        case EAFNOSUPPORT:
        case EPROTONOSUPPORT:
        case ESOCKTNOSUPPORT:
        case ENOSYS:
        case EADDRNOTAVAIL:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] inline SocketCapability socket_failure(int error_number, std::string_view operation) noexcept
{
    return SocketCapability{false, is_unavailable_socket_error(error_number), error_number, operation};
}

// Probe once at executable startup. Keeping the probe outside individual test
// cases prevents a restricted sandbox from turning part of a socket suite into
// a silent success. Only explicit denial/unsupported errors are skippable;
// resource exhaustion and broken I/O remain real test failures.
[[nodiscard]] inline SocketCapability probe_unix_datagram_io() noexcept
{
    int sockets[2]{-1, -1};
    if (::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) != 0)
        return socket_failure(errno, "socketpair(AF_UNIX datagram)");

    runtime::UniqueFd sender{sockets[0]};
    runtime::UniqueFd receiver{sockets[1]};
    const std::byte   sent_value{0x5a};
    ssize_t           sent;
    do
    {
        sent = ::send(sender.get(), &sent_value, sizeof(sent_value), 0);
    } while (sent < 0 && errno == EINTR);
    if (sent != static_cast<ssize_t>(sizeof(sent_value)))
        return socket_failure(sent < 0 ? errno : EIO, "send(AF_UNIX datagram)");

    std::byte received_value{};
    ssize_t   received;
    do
    {
        received = ::recv(receiver.get(), &received_value, sizeof(received_value), 0);
    } while (received < 0 && errno == EINTR);
    if (received != static_cast<ssize_t>(sizeof(received_value)) || received_value != sent_value)
        return socket_failure(received < 0 ? errno : EIO, "recv(AF_UNIX datagram)");

    return SocketCapability{true, false, 0, {}};
}

[[nodiscard]] inline SocketCapability probe_ipv4_loopback_datagram_io() noexcept
{
    runtime::UniqueFd loopback_receiver{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (!loopback_receiver)
        return socket_failure(errno, "socket(AF_INET receiver)");
    runtime::UniqueFd loopback_sender{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (!loopback_sender)
        return socket_failure(errno, "socket(AF_INET sender)");

    sockaddr_in receiver_address{};
    receiver_address.sin_family      = AF_INET;
    receiver_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    receiver_address.sin_port        = 0;
    if (::bind(loopback_receiver.get(), reinterpret_cast<const sockaddr *>(&receiver_address), sizeof(receiver_address)) != 0)
        return socket_failure(errno, "bind(AF_INET loopback)");

    socklen_t receiver_address_size = sizeof(receiver_address);
    if (::getsockname(loopback_receiver.get(), reinterpret_cast<sockaddr *>(&receiver_address), &receiver_address_size) != 0)
        return socket_failure(errno, "getsockname(AF_INET loopback)");

    const std::byte sent_value{0x5a};
    ssize_t         sent;

    do
    {
        sent = ::sendto(loopback_sender.get(), &sent_value, sizeof(sent_value), 0,
                        reinterpret_cast<const sockaddr *>(&receiver_address), receiver_address_size);
    } while (sent < 0 && errno == EINTR);
    if (sent != static_cast<ssize_t>(sizeof(sent_value)))
        return socket_failure(sent < 0 ? errno : EIO, "sendto(AF_INET loopback)");

    pollfd readable{loopback_receiver.get(), POLLIN, 0};
    int    poll_result;
    do
    {
        poll_result = ::poll(&readable, 1, 250);
    } while (poll_result < 0 && errno == EINTR);
    if (poll_result <= 0)
        return socket_failure(poll_result < 0 ? errno : ETIMEDOUT, "poll(AF_INET loopback)");
    if ((readable.revents & POLLIN) == 0)
        return socket_failure(EIO, "poll(AF_INET loopback readiness)");

    std::byte received_value{};
    ssize_t   received;
    do
    {
        received = ::recvfrom(loopback_receiver.get(), &received_value, sizeof(received_value), 0, nullptr, nullptr);
    } while (received < 0 && errno == EINTR);
    if (received != static_cast<ssize_t>(sizeof(received_value)) || received_value != sent_value)
        return socket_failure(received < 0 ? errno : EIO, "recvfrom(AF_INET loopback)");

    return SocketCapability{true, false, 0, {}};
}

[[nodiscard]] inline int socket_test_unavailable_exit(const SocketCapability capability, std::string_view suite_name)
{
    std::cerr << suite_name << ": datagram socket capability probe failed during " << capability.operation;
    if (capability.error_number != 0)
        std::cerr << ": " << std::strerror(capability.error_number) << " (errno=" << capability.error_number << ')';

    if (!capability.skippable)
    {
        std::cerr << "; treating an unexpected probe failure as a test failure\n";
        return EXIT_FAILURE;
    }

#if DNS_PRO_REQUIRE_SOCKET_TESTS
    std::cerr << "; DNS_PRO_REQUIRE_SOCKET_TESTS is enabled\n";
    return EXIT_FAILURE;
#else
    std::cerr << "; skipping the complete socket test executable\n";
    return kSocketTestSkipReturnCode;
#endif
}

} // namespace dns::test
