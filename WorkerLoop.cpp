#include "WorkerLoop.h"

#include "protocol/DnsParser.h"
#include "protocol/DnsQuery.h"
#include "protocol/DnsWriter.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <span>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <utility>
#include <vector>

namespace dns::server
{
namespace
{

Unexpected<WorkerInitError> init_failure(WorkerInitStep step) noexcept
{
    return dns::unexpected(WorkerInitError{step, errno});
}

} // namespace

DatagramDecision WorkerLoop::evaluate_datagram(std::span<const std::byte> packet, bool truncated)
{
    if (truncated)
    {
        auto format_error = protocol::make_format_error_response(packet);
        return DatagramDecision{DatagramOutcome::Truncated, format_error ? std::move(*format_error) : std::vector<std::byte>{}};
    }

    auto parsed = protocol::parse_message(packet);
    if (!parsed)
    {
        auto format_error = protocol::make_format_error_response(packet);
        return DatagramDecision{DatagramOutcome::Malformed, format_error ? std::move(*format_error) : std::vector<std::byte>{}};
    }

    auto query = protocol::validate_mvp_query(*parsed);
    if (!query)
    {
        if (query.error().code == protocol::QueryErrorCode::NotAQuery)
            return DatagramDecision{DatagramOutcome::Dropped, {}};

        auto response = protocol::make_error_response(*parsed, protocol::response_code_for(query.error().code), true, kMaximumDatagramSize);
        if (!response)
            return DatagramDecision{DatagramOutcome::InternalError, {}};
        return DatagramDecision{DatagramOutcome::Unsupported, std::move(*response)};
    }

    auto response = protocol::make_error_response(*parsed, protocol::ResponseCode::ServFail, true, kMaximumDatagramSize);
    if (!response)
        return DatagramDecision{DatagramOutcome::InternalError, {}};
    return DatagramDecision{DatagramOutcome::Accepted, std::move(*response)};
}

WorkerLoop::CreateResult WorkerLoop::create(size_t worker_id, uint16_t port, Cache::CacheShard &cache_shard)
{
    auto worker = std::unique_ptr<WorkerLoop>{new WorkerLoop{worker_id, cache_shard}};
    auto initialized = worker->initialize(port);
    if (!initialized)
        return dns::unexpected(initialized.error());
    return worker;
}

Expected<void, WorkerInitError> WorkerLoop::initialize(uint16_t port)
{
    runtime::UniqueFd listener{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (!listener)
        return init_failure(WorkerInitStep::CreateSocket);

    int enabled = 1;
    if (::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) < 0 ||
        ::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)) < 0)
        return init_failure(WorkerInitStep::ConfigureSocket);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (::bind(listener.get(), reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0)
        return init_failure(WorkerInitStep::BindSocket);

    socklen_t address_length = sizeof(address);
    if (::getsockname(listener.get(), reinterpret_cast<sockaddr *>(&address), &address_length) < 0)
        return init_failure(WorkerInitStep::ReadBoundAddress);

    runtime::UniqueFd epoll{::epoll_create1(EPOLL_CLOEXEC)};
    if (!epoll)
        return init_failure(WorkerInitStep::CreateEpoll);

    runtime::UniqueFd wake{::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)};
    if (!wake)
        return init_failure(WorkerInitStep::CreateWakeEvent);

    epoll_event listener_event{};
    listener_event.events = EPOLLIN | EPOLLET;
    listener_event.data.u64 = static_cast<uint64_t>(EventKind::Listener);
    if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, listener.get(), &listener_event) < 0)
        return init_failure(WorkerInitStep::RegisterListener);

    epoll_event wake_event{};
    wake_event.events = EPOLLIN;
    wake_event.data.u64 = static_cast<uint64_t>(EventKind::Wake);
    if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, wake.get(), &wake_event) < 0)
        return init_failure(WorkerInitStep::RegisterWakeEvent);

    bound_port_ = ntohs(address.sin_port);
    listen_fd_ = std::move(listener);
    epoll_fd_ = std::move(epoll);
    wake_fd_ = std::move(wake);
    return {};
}

void WorkerLoop::run(std::stop_token stop_token) noexcept
{
    std::array<epoll_event, 64> events{};

    while (!stop_token.stop_requested())
    {
        const int ready = ::epoll_wait(epoll_fd_.get(), events.data(), static_cast<int>(events.size()), -1);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
            std::cerr << "worker " << worker_id_ << " epoll_wait failed: " << std::strerror(errno) << '\n';
            break;
        }

        for (int index = 0; index < ready; ++index)
        {
            const auto kind = static_cast<EventKind>(events[static_cast<size_t>(index)].data.u64);
            if (kind == EventKind::Wake)
            {
                drain_wakeup();
                continue;
            }
            if (kind == EventKind::Listener)
                drain_listener(stop_token);
        }
    }
}

void WorkerLoop::request_stop() const noexcept
{
    if (!wake_fd_)
        return;

    const uint64_t value = 1;
    ssize_t        result;
    do
    {
        result = ::write(wake_fd_.get(), &value, sizeof(value));
    } while (result < 0 && errno == EINTR);
}

void WorkerLoop::drain_wakeup() const noexcept
{
    uint64_t value{0};
    while (::read(wake_fd_.get(), &value, sizeof(value)) < 0 && errno == EINTR)
    {
    }
}

void WorkerLoop::drain_listener(std::stop_token stop_token) noexcept
{
    std::array<std::byte, kMaximumDatagramSize> buffer{};

    while (!stop_token.stop_requested())
    {
        sockaddr_storage client_address{};
        iovec            io_vector{buffer.data(), buffer.size()};
        msghdr           message{};
        message.msg_name = &client_address;
        message.msg_namelen = sizeof(client_address);
        message.msg_iov = &io_vector;
        message.msg_iovlen = 1;

        const ssize_t received = ::recvmsg(listen_fd_.get(), &message, MSG_TRUNC);
        if (received < 0)
        {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            std::cerr << "worker " << worker_id_ << " recvmsg failed: " << std::strerror(errno) << '\n';
            return;
        }

        ++stats_.received_datagrams;
        const bool truncated = (message.msg_flags & MSG_TRUNC) != 0 || static_cast<size_t>(received) > buffer.size();
        const size_t available = std::min(static_cast<size_t>(received), buffer.size());
        process_datagram(buffer.data(), available, reinterpret_cast<const sockaddr *>(&client_address), message.msg_namelen, truncated);
    }
}

void WorkerLoop::process_datagram(const std::byte *data,
                                  size_t           size,
                                  const sockaddr  *client_address,
                                  socklen_t        client_length,
                                  bool             truncated) noexcept
{
    try
    {
        const std::span<const std::byte> packet{data, size};
        DatagramDecision decision = evaluate_datagram(packet, truncated);
        switch (decision.outcome)
        {
            case DatagramOutcome::Dropped:
                return;
            case DatagramOutcome::Truncated:
                ++stats_.truncated_datagrams;
                break;
            case DatagramOutcome::Malformed:
                ++stats_.parse_errors;
                break;
            case DatagramOutcome::Unsupported:
                ++stats_.unsupported_queries;
                break;
            case DatagramOutcome::Accepted:
                ++stats_.accepted_queries;
                break;
            case DatagramOutcome::InternalError:
                ++stats_.internal_errors;
                return;
        }

        if (!decision.response.empty())
            send_response(decision.response, client_address, client_length);
    }
    catch (const std::exception &error)
    {
        ++stats_.internal_errors;
        std::cerr << "worker " << worker_id_ << " failed to process datagram: " << error.what() << '\n';
    }
}

void WorkerLoop::send_response(const std::vector<std::byte> &response, const sockaddr *client_address, socklen_t client_length) noexcept
{
    ssize_t sent;
    do
    {
        sent = ::sendto(listen_fd_.get(), response.data(), response.size(), 0, client_address, client_length);
    } while (sent < 0 && errno == EINTR);

    if (sent == static_cast<ssize_t>(response.size()))
        ++stats_.responses_sent;
    else
    {
        ++stats_.send_errors;
        std::cerr << "worker " << worker_id_ << " sendto failed: " << std::strerror(errno) << '\n';
    }
}

} // namespace dns::server
