#include "DNS.h"
#include "protocol/DnsParser.h"
#include "protocol/DnsWriter.h"
#include "runtime/UniqueFd.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <span>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <utility>
#include <vector>

namespace
{

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "reactor test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

std::vector<std::byte> make_query(uint16_t id, dns::protocol::RecordType type)
{
    auto name = dns::protocol::DomainName::from_text("Example.COM.");
    require(name.has_value(), "query fixture name must be valid");

    dns::protocol::Header header;
    header.id = id;
    header.recursion_desired = true;
    const std::array questions{dns::protocol::Question{std::move(*name), static_cast<uint16_t>(type),
                                                       static_cast<uint16_t>(dns::protocol::RecordClass::IN)}};
    auto wire = dns::protocol::serialize_query(header, questions);
    require(wire.has_value(), "query fixture must serialize");
    return std::move(*wire);
}

std::vector<std::byte> exchange(int client_fd, uint16_t port, std::span<const std::byte> request, std::string_view case_name)
{
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port = htons(port);

    const ssize_t sent = ::sendto(client_fd, request.data(), request.size(), 0, reinterpret_cast<const sockaddr *>(&server), sizeof(server));
    require(sent == static_cast<ssize_t>(request.size()), "client must send the complete UDP query");

    std::array<std::byte, 4096> response{};
    const ssize_t received = ::recvfrom(client_fd, response.data(), response.size(), 0, nullptr, nullptr);
    if (received <= 0)
    {
        std::cerr << "reactor exchange timed out for " << case_name << ", errno=" << errno << '\n';
        require(false, "worker reactor must return a UDP response before timeout");
    }
    return {response.begin(), response.begin() + static_cast<std::ptrdiff_t>(received)};
}

void send_query(int client_fd, uint16_t port, std::span<const std::byte> request)
{
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port = htons(port);
    require(::sendto(client_fd, request.data(), request.size(), 0, reinterpret_cast<const sockaddr *>(&server), sizeof(server)) ==
                static_cast<ssize_t>(request.size()),
            "queued datagram fixture must be sent completely");
}

std::vector<std::byte> receive_response(int client_fd, std::string_view client_name)
{
    std::array<std::byte, 4096> response{};
    const ssize_t received = ::recvfrom(client_fd, response.data(), response.size(), 0, nullptr, nullptr);
    if (received <= 0)
    {
        std::cerr << "reactor receive timed out for " << client_name << ", errno=" << errno << '\n';
        require(false, "each queued client must receive its own response");
    }
    return {response.begin(), response.begin() + static_cast<std::ptrdiff_t>(received)};
}

void test_owned_datagrams_survive_initial_suspend()
{
    Cache::DNS_Cache cache{8, 1};
    auto worker_result = dns::server::WorkerLoop::create(0, 0, cache.shard(0));
    if (!worker_result)
    {
        std::cout << "owned datagram socket test skipped by sandbox\n";
        return;
    }
    auto worker = std::move(*worker_result);

    dns::runtime::UniqueFd first_client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    dns::runtime::UniqueFd second_client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(first_client && second_client, "two UDP client fixtures must be created");
    timeval timeout{1, 0};
    require(::setsockopt(first_client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
                ::setsockopt(second_client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "queued client receive timeouts must be configured");

    // Queue both packets before run(). The EPOLLET drain therefore reuses its
    // stack buffer and sockaddr for both packets before either lazy root runs.
    send_query(first_client.get(), worker->bound_port(), make_query(0x1111, dns::protocol::RecordType::A));
    send_query(second_client.get(), worker->bound_port(), make_query(0x2222, dns::protocol::RecordType::AAAA));

    constexpr size_t   burst_size = 80;
    constexpr uint16_t first_burst_id = 0x3000;
    for (size_t index = 0; index < burst_size; ++index)
    {
        const auto id = static_cast<uint16_t>(static_cast<size_t>(first_burst_id) + index);
        send_query(first_client.get(), worker->bound_port(), make_query(id, dns::protocol::RecordType::A));
    }

    // All 82 packets are now queued before the worker starts, so more than one
    // receive budget must be drained without relying on a second EPOLLET edge.
    std::jthread worker_thread{[loop = worker.get()](std::stop_token token) { loop->run(token); }};
    auto second_wire = receive_response(second_client.get(), "second client");
    auto second = dns::protocol::parse_message(second_wire);
    require(second && second->header.id == 0x2222, "second coroutine must retain the second packet and client address");

    std::array<bool, burst_size> seen{};
    bool                         first_seen = false;
    for (size_t index = 0; index < burst_size + 1; ++index)
    {
        static_cast<void>(index);
        auto wire = receive_response(first_client.get(), "first/burst client");
        auto response = dns::protocol::parse_message(wire);
        require(static_cast<bool>(response), "every owned datagram response must remain parseable");
        if (response->header.id == 0x1111)
        {
            first_seen = true;
            continue;
        }
        require(response->header.id >= first_burst_id && static_cast<size_t>(response->header.id - first_burst_id) < burst_size,
                "every burst response must retain one of its queued transaction IDs");
        seen[static_cast<size_t>(response->header.id - first_burst_id)] = true;
    }
    require(first_seen && std::all_of(seen.begin(), seen.end(), [](bool value) { return value; }),
            "ready work beyond one receive/resume budget must not sleep in epoll_wait");

    worker->request_stop();
    worker_thread.join();

    constexpr uint64_t expected_datagrams = 2 + static_cast<uint64_t>(burst_size);
    require(worker->stats().received_datagrams == expected_datagrams && worker->stats().accepted_queries == expected_datagrams &&
                worker->stats().responses_sent == expected_datagrams,
            "all owned datagram roots must complete before shutdown");
}

void test_udp_reactor_responses()
{
    DNS service;
    DNSConfig config;
    config.worker_count = 1;
    config.manager_count = 0;
    config.cache_capacity = 8;
    config.port = 0;
    require(service.init(config), "reactor service fixture must initialize");

    if (!service.start())
    {
        // Restricted sandboxes can deny socket(2); the same executable is run
        // with local-socket permission during verification.
        std::cout << "reactor socket test skipped by sandbox\n";
        return;
    }

    const auto port = service.bound_port();
    require(port && *port != 0, "port-zero binding must publish the assigned local port");

    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "UDP client fixture must be created");
    timeval timeout{1, 0};
    require(::setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "client receive timeout must be configured");

    auto a_response_wire = exchange(client.get(), *port, make_query(0x1234, dns::protocol::RecordType::A), "A query");
    auto a_response = dns::protocol::parse_message(a_response_wire);
    require(a_response && a_response->header.is_response && a_response->header.id == 0x1234,
            "reactor response must preserve QR and transaction ID");
    require(a_response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::ServFail),
            "supported MVP queries must receive fixed SERVFAIL before upstream resolution exists");
    require(a_response->questions.size() == 1 && a_response->questions.front().name.to_canonical_string() == "example.com",
            "fixed response must echo the validated question");

    auto mx_response_wire = exchange(client.get(), *port, make_query(0x2345, dns::protocol::RecordType::MX), "MX query");
    auto mx_response = dns::protocol::parse_message(mx_response_wire);
    require(mx_response && mx_response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::NotImp),
            "unsupported QTYPE must receive NOTIMP");

    const std::array malformed{std::byte{0x34}, std::byte{0x56}, std::byte{0x01}, std::byte{0x00},
                               std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                               std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    auto malformed_response_wire = exchange(client.get(), *port, malformed, "malformed query");
    auto malformed_response = dns::protocol::parse_message(malformed_response_wire);
    require(malformed_response && malformed_response->header.id == 0x3456 &&
                malformed_response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::FormErr),
            "truncated query sections must receive header-only FORMERR");

    const std::array response_packet{std::byte{0x56}, std::byte{0x78}, std::byte{0x80}, std::byte{0x00},
                                     std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                     std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port = htons(*port);
    require(::sendto(client.get(), response_packet.data(), response_packet.size(), 0, reinterpret_cast<const sockaddr *>(&server), sizeof(server)) ==
                static_cast<ssize_t>(response_packet.size()),
            "response-loop fixture must be sent");
    std::array<std::byte, 64> no_response{};
    errno = 0;
    require(::recvfrom(client.get(), no_response.data(), no_response.size(), 0, nullptr, nullptr) == -1 &&
                (errno == EAGAIN || errno == EWOULDBLOCK),
            "the reactor must silently drop QR=1 packets instead of creating a response loop");

    service.request_stop();
    service.join();
    require(!service.is_running(), "eventfd must stop an epoll-blocked reactor after traffic");
}

void test_truncated_datagram_decision()
{
    const std::array prefix{std::byte{0x45}, std::byte{0x67}, std::byte{0x01}, std::byte{0x00}};
    auto decision = dns::server::WorkerLoop::evaluate_datagram(prefix, true);
    require(decision.outcome == dns::server::DatagramOutcome::Truncated, "MSG_TRUNC must bypass normal packet parsing");
    auto response = dns::protocol::parse_message(decision.response);
    require(response && response->header.id == 0x4567 &&
                response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::FormErr),
            "a truncated query with an ID must produce header-only FORMERR");
}

} // namespace

int main()
{
    test_truncated_datagram_decision();
    test_owned_datagrams_survive_initial_suspend();
    test_udp_reactor_responses();
    std::cout << "all reactor tests passed\n";
    return EXIT_SUCCESS;
}
