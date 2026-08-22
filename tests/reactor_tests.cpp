#include "DNS.h"
#include "protocol/DnsLimits.h"
#include "protocol/DnsParser.h"
#include "protocol/DnsWriter.h"
#include "runtime/UniqueFd.h"
#include "tests/SocketTestSupport.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <utility>
#include <vector>

namespace dns::server
{

struct WorkerLoopTestPeer
{
    static void send_response(WorkerLoop &worker, const std::vector<std::byte> &response, const sockaddr *client_address,
                              socklen_t client_length) noexcept
    {
        worker.send_response(response, client_address, client_length);
    }
};

} // namespace dns::server

namespace
{

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "reactor test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

class CapturedWorkerThread final
{
public:
    explicit CapturedWorkerThread(dns::server::WorkerLoop *worker)
        : thread_([this, worker](std::stop_token token) { result_ = worker->run(token); })
    {
    }

    void join()
    {
        thread_.join();
        require(result_ && result_->outcome == dns::server::WorkerRunOutcome::RequestedStop && !result_->error,
                "a directly-run worker must report a structured RequestedStop result");
    }

private:
    std::optional<dns::server::WorkerRunResult> result_;
    std::jthread                                thread_;
};

struct BlackholeUpstream
{
    dns::runtime::UniqueFd socket;
    uint16_t               port{0};
};

std::optional<BlackholeUpstream> make_blackhole_upstream()
{
    dns::runtime::UniqueFd socket{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    if (!socket)
        return std::nullopt;

    sockaddr_in address{};
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port        = 0;
    if (::bind(socket.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) < 0)
        return std::nullopt;

    timeval timeout{1, 0};
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        return std::nullopt;

    socklen_t address_length = sizeof(address);
    if (::getsockname(socket.get(), reinterpret_cast<sockaddr *>(&address), &address_length) < 0)
        return std::nullopt;
    return BlackholeUpstream{std::move(socket), ntohs(address.sin_port)};
}

dns::server::UpstreamConfig blackhole_config(uint16_t port)
{
    dns::server::UpstreamConfig config;
    config.port           = port;
    config.query_timeout  = std::chrono::milliseconds{10};
    config.id_reuse_guard = std::chrono::milliseconds{20};
    return config;
}

std::vector<std::byte> make_query(uint16_t id, dns::protocol::RecordType type, std::string_view domain = "Example.COM.",
                                  bool checking_disabled = false, bool authenticated_data = false)
{
    auto name = dns::protocol::DomainName::from_text(domain);
    require(name.has_value(), "query fixture name must be valid");

    dns::protocol::Header header;
    header.id                 = id;
    header.recursion_desired  = true;
    header.checking_disabled  = checking_disabled;
    header.authenticated_data = authenticated_data;
    const std::array questions{
        dns::protocol::Question{std::move(*name), static_cast<uint16_t>(type), static_cast<uint16_t>(dns::protocol::RecordClass::IN)}};
    auto wire = dns::protocol::serialize_query(header, questions);
    require(wire.has_value(), "query fixture must serialize");
    return std::move(*wire);
}

std::vector<std::byte> make_exact_size_opt_query(uint16_t id, size_t target_size)
{
    auto             wire              = make_query(id, dns::protocol::RecordType::A);
    constexpr size_t opt_envelope_size = 11;
    require(wire.size() + opt_envelope_size <= target_size, "OPT boundary fixture must have room for its RR envelope");

    const size_t rdata_size = target_size - wire.size() - opt_envelope_size;
    require(rdata_size <= 65'535, "OPT boundary fixture RDATA must fit RDLENGTH");
    wire[10] = std::byte{0};
    wire[11] = std::byte{1};
    wire.push_back(std::byte{0}); // root owner
    wire.push_back(std::byte{0});
    wire.push_back(std::byte{0x29}); // OPT
    wire.push_back(std::byte{0x02});
    wire.push_back(std::byte{0}); // advertised UDP payload size 512
    wire.insert(wire.end(), 4, std::byte{0});
    wire.push_back(static_cast<std::byte>((rdata_size >> 8U) & 0xffU));
    wire.push_back(static_cast<std::byte>(rdata_size & 0xffU));
    wire.insert(wire.end(), rdata_size, std::byte{0x5a});
    require(wire.size() == target_size && dns::protocol::parse_message(wire).has_value(),
            "OPT boundary fixture must remain an envelope-valid DNS query");
    return wire;
}

std::vector<std::byte> make_a_rrset_response(std::span<const std::byte> query)
{
    auto request = dns::protocol::parse_message(query);
    require(request && request->questions.size() == 1 && request->questions.front().type == static_cast<uint16_t>(dns::protocol::RecordType::A),
            "forwarded A query fixture must parse");

    const std::array first{std::byte{192}, std::byte{0}, std::byte{2}, std::byte{10}};
    const std::array second{std::byte{192}, std::byte{0}, std::byte{2}, std::byte{11}};
    const std::array answers{dns::protocol::AddressAnswerView{first}, dns::protocol::AddressAnswerView{second}};
    auto             response = dns::protocol::make_address_response(*request, answers, 60);
    require(response.has_value(), "fake upstream A RRset must serialize");
    return std::move(*response);
}

std::vector<std::byte> make_aaaa_rrset_response(std::span<const std::byte> query)
{
    auto request = dns::protocol::parse_message(query);
    require(request && request->questions.size() == 1 && request->questions.front().type == static_cast<uint16_t>(dns::protocol::RecordType::AAAA),
            "forwarded AAAA query fixture must parse");

    std::array<std::byte, 16> first{};
    std::array<std::byte, 16> second{};
    first[15]  = std::byte{1};
    second[15] = std::byte{2};
    const std::array answers{dns::protocol::AddressAnswerView{first}, dns::protocol::AddressAnswerView{second}};
    auto             response = dns::protocol::make_address_response(*request, answers, 45);
    require(response.has_value(), "fake upstream AAAA RRset must serialize");
    return std::move(*response);
}

std::vector<std::byte> make_a_response(std::span<const std::byte> query)
{
    require(query.size() >= dns::protocol::kDnsHeaderSize, "forwarded query must contain a DNS header");
    std::vector<std::byte> response{query.begin(), query.end()};
    response[2]  = std::byte{0x81}; // QR + RD
    response[3]  = std::byte{0x80}; // RA + NOERROR
    response[6]  = std::byte{0x00};
    response[7]  = std::byte{0x01}; // one answer
    response[8]  = std::byte{0x00};
    response[9]  = std::byte{0x00};
    response[10] = std::byte{0x00};
    response[11] = std::byte{0x00};

    constexpr std::array answer{
        std::byte{0xc0}, std::byte{0x0c},                                   // owner = first question
        std::byte{0x00}, std::byte{0x01},                                   // A
        std::byte{0x00}, std::byte{0x01},                                   // IN
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x3c}, // TTL 60
        std::byte{0x00}, std::byte{0x04},                                   // RDLENGTH
        std::byte{203},  std::byte{0},    std::byte{113},  std::byte{7},
    };
    response.insert(response.end(), answer.begin(), answer.end());
    return response;
}

std::vector<std::byte> exchange(int client_fd, uint16_t port, std::span<const std::byte> request, std::string_view case_name)
{
    sockaddr_in server{};
    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port        = htons(port);

    const ssize_t sent = ::sendto(client_fd, request.data(), request.size(), 0, reinterpret_cast<const sockaddr *>(&server), sizeof(server));
    require(sent == static_cast<ssize_t>(request.size()), "client must send the complete UDP query");

    std::array<std::byte, 4096> response{};
    const ssize_t               received = ::recvfrom(client_fd, response.data(), response.size(), 0, nullptr, nullptr);
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
    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port        = htons(port);
    require(::sendto(client_fd, request.data(), request.size(), 0, reinterpret_cast<const sockaddr *>(&server), sizeof(server)) ==
                static_cast<ssize_t>(request.size()),
            "queued datagram fixture must be sent completely");
}

std::vector<std::byte> receive_response(int client_fd, std::string_view client_name)
{
    std::array<std::byte, 4096> response{};
    const ssize_t               received = ::recvfrom(client_fd, response.data(), response.size(), 0, nullptr, nullptr);
    if (received <= 0)
    {
        std::cerr << "reactor receive timed out for " << client_name << ", errno=" << errno << '\n';
        require(false, "each queued client must receive its own response");
    }
    return {response.begin(), response.begin() + static_cast<std::ptrdiff_t>(received)};
}

struct ForwardedQuery
{
    std::vector<std::byte> packet;
    sockaddr_storage       worker_address{};
    socklen_t              worker_address_length{0};
};

ForwardedQuery receive_forwarded_query(BlackholeUpstream &upstream, std::string_view case_name)
{
    std::array<std::byte, 4096> buffer{};
    ForwardedQuery              query;
    query.worker_address_length = sizeof(query.worker_address);
    const ssize_t received = ::recvfrom(upstream.socket.get(), buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr *>(&query.worker_address),
                                        &query.worker_address_length);
    if (received <= 0)
    {
        std::cerr << "upstream receive timed out for " << case_name << ", errno=" << errno << '\n';
        require(false, "an uncached query must reach the fake upstream");
    }
    query.packet.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(received));
    return query;
}

void send_upstream_response(BlackholeUpstream &upstream, const ForwardedQuery &query, std::span<const std::byte> response)
{
    require(::sendto(upstream.socket.get(), response.data(), response.size(), 0, reinterpret_cast<const sockaddr *>(&query.worker_address),
                     query.worker_address_length) == static_cast<ssize_t>(response.size()),
            "the fake upstream must send its complete response");
}

void test_owned_datagrams_survive_initial_suspend()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "owned-datagram upstream fixture must initialize after the suite capability probe");

    Cache::DNS_Cache cache{8, 1};
    auto             worker_result = dns::server::WorkerLoop::create(0, 0, cache.shard(0), blackhole_config(upstream->port));
    require(worker_result.has_value(), "owned-datagram worker fixture must initialize after the suite capability probe");
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

    constexpr size_t   burst_size     = 80;
    constexpr uint16_t first_burst_id = 0x3000;
    for (size_t index = 0; index < burst_size; ++index)
    {
        const auto id = static_cast<uint16_t>(static_cast<size_t>(first_burst_id) + index);
        send_query(first_client.get(), worker->bound_port(), make_query(id, dns::protocol::RecordType::A));
    }

    // All 82 packets are now queued before the worker starts, so more than one
    // receive budget must be drained without relying on a second EPOLLET edge.
    CapturedWorkerThread worker_thread{worker.get()};
    auto                 second_wire = receive_response(second_client.get(), "second client");
    auto                 second      = dns::protocol::parse_message(second_wire);
    require(second && second->header.id == 0x2222, "second coroutine must retain the second packet and client address");

    std::array<bool, burst_size> seen{};
    bool                         first_seen = false;
    for (size_t index = 0; index < burst_size + 1; ++index)
    {
        static_cast<void>(index);
        auto wire     = receive_response(first_client.get(), "first/burst client");
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
                worker->stats().responses_sent == expected_datagrams && worker->stats().upstream_timeouts == expected_datagrams,
            "all owned datagram roots must retain ownership and complete through their upstream deadlines");
}

void test_udp_reactor_responses()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "reactor upstream fixture must initialize after the suite capability probe");

    DNS       service;
    DNSConfig config;
    config.worker_count            = 1;
    config.runtime_updates_enabled = false;
    config.cache_capacity          = 8;
    config.port                    = 0;
    config.upstream                = blackhole_config(upstream->port);
    require(service.init(config), "reactor service fixture must initialize");

    const auto started = service.start();
    require(static_cast<bool>(started), "reactor service fixture must start after the suite capability probe");

    const auto port = service.bound_port();
    require(port && *port != 0, "port-zero binding must publish the assigned local port");

    auto disabled_update = service.replace_blocked_domains({"disabled.example"});
    require(!disabled_update && disabled_update.error().code == dns::server::FilterUpdateErrorCode::ControlPlaneDisabled,
            "a running service without an update coordinator must reject runtime reload without blocking");

    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "UDP client fixture must be created");
    timeval timeout{1, 0};
    require(::setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "client receive timeout must be configured");

    auto a_response_wire = exchange(client.get(), *port, make_query(0x1234, dns::protocol::RecordType::A), "A query");
    auto a_response      = dns::protocol::parse_message(a_response_wire);
    require(a_response && a_response->header.is_response && a_response->header.id == 0x1234, "reactor response must preserve QR and transaction ID");
    require(a_response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::ServFail),
            "an unanswered upstream query must become SERVFAIL after its deadline");
    require(a_response->questions.size() == 1 && a_response->questions.front().name.to_canonical_string() == "example.com",
            "the timeout response must echo the validated question");

    auto mx_response_wire = exchange(client.get(), *port, make_query(0x2345, dns::protocol::RecordType::MX), "MX query");
    auto mx_response      = dns::protocol::parse_message(mx_response_wire);
    require(mx_response && mx_response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::NotImp),
            "unsupported QTYPE must receive NOTIMP");

    for (const size_t query_size : {size_t{511}, dns::protocol::kClassicDnsUdpPayloadLimit})
    {
        const uint16_t id                = query_size == 511 ? uint16_t{0x2501} : uint16_t{0x2502};
        auto           opt_response_wire = exchange(client.get(), *port, make_exact_size_opt_query(id, query_size), "classic UDP OPT boundary query");
        auto           opt_response      = dns::protocol::parse_message(opt_response_wire);
        require(opt_response && opt_response->header.id == id &&
                    opt_response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::NotImp) &&
                    opt_response->questions.size() == 1 && opt_response->answers.empty() && opt_response->authorities.empty() &&
                    opt_response->additionals.empty(),
                "an envelope-valid OPT query at 511/512 bytes must receive NOTIMP on its first response");
    }

    const std::array malformed{std::byte{0x34}, std::byte{0x56}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                               std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    auto             malformed_response_wire = exchange(client.get(), *port, malformed, "malformed query");
    auto             malformed_response      = dns::protocol::parse_message(malformed_response_wire);
    require(malformed_response && malformed_response->header.id == 0x3456 &&
                malformed_response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::FormErr),
            "truncated query sections must receive header-only FORMERR");

    auto oversized_query = make_query(0x4567, dns::protocol::RecordType::A);
    oversized_query.resize(dns::protocol::kDownstreamReceiveBufferSize + 1, std::byte{0});
    auto oversized_query_response_wire = exchange(client.get(), *port, oversized_query, "oversized query");
    auto oversized_query_response      = dns::protocol::parse_message(oversized_query_response_wire);
    require(oversized_query_response && oversized_query_response_wire.size() == dns::protocol::kDnsHeaderSize &&
                oversized_query_response->header.id == 0x4567 &&
                oversized_query_response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::FormErr) &&
                oversized_query_response->questions.empty() && oversized_query_response->answers.empty() &&
                oversized_query_response->authorities.empty() && oversized_query_response->additionals.empty(),
            "a 513-byte downstream query must receive only a header-only FORMERR");

    const std::array response_packet{std::byte{0x56}, std::byte{0x78}, std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                     std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    sockaddr_in      server{};
    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port        = htons(*port);
    require(::sendto(client.get(), response_packet.data(), response_packet.size(), 0, reinterpret_cast<const sockaddr *>(&server), sizeof(server)) ==
                static_cast<ssize_t>(response_packet.size()),
            "response-loop fixture must be sent");
    std::vector<std::byte> oversized_response(dns::protocol::kDownstreamReceiveBufferSize + 1, std::byte{0});
    std::copy(response_packet.begin(), response_packet.end(), oversized_response.begin());
    require(::sendto(client.get(), oversized_response.data(), oversized_response.size(), 0, reinterpret_cast<const sockaddr *>(&server),
                     sizeof(server)) == static_cast<ssize_t>(oversized_response.size()),
            "oversized response-loop fixture must be sent");
    std::array<std::byte, 64> no_response{};
    errno = 0;
    require(::recvfrom(client.get(), no_response.data(), no_response.size(), 0, nullptr, nullptr) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
            "the reactor must silently drop both ordinary and oversized QR=1 packets instead of creating a response loop");

    service.request_stop();
    const auto exit = service.join();
    require(exit.code == DNSServiceExitCode::ExplicitStop, "reactor service shutdown must report ExplicitStop");
    require(!service.is_running(), "eventfd must stop an epoll-blocked reactor after traffic");
}

void test_upstream_response_is_forwarded()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "forwarding upstream fixture must initialize after the suite capability probe");

    Cache::DNS_Cache cache{8, 1};
    auto             upstream_config = blackhole_config(upstream->port);
    upstream_config.query_timeout    = std::chrono::milliseconds{500};
    upstream_config.id_reuse_guard   = std::chrono::milliseconds{500};
    auto worker_result               = dns::server::WorkerLoop::create(0, 0, cache.shard(0), upstream_config);
    require(worker_result.has_value(), "forwarding worker fixture must initialize");
    auto worker = std::move(*worker_result);

    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "forwarding client fixture must be created");
    timeval timeout{1, 0};
    require(::setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "forwarding client receive timeout must be configured");

    CapturedWorkerThread worker_thread{worker.get()};
    send_query(client.get(), worker->bound_port(), make_query(0xbeef, dns::protocol::RecordType::A));

    std::array<std::byte, 4096> forwarded_buffer{};
    sockaddr_storage            worker_address{};
    socklen_t                   worker_address_length = sizeof(worker_address);
    const ssize_t               forwarded             = ::recvfrom(upstream->socket.get(), forwarded_buffer.data(), forwarded_buffer.size(), 0,
                                                                   reinterpret_cast<sockaddr *>(&worker_address), &worker_address_length);
    require(forwarded > 0, "the worker must send a rewritten query to its configured upstream");

    const std::span<const std::byte> forwarded_query{forwarded_buffer.data(), static_cast<size_t>(forwarded)};
    auto                             parsed_forwarded = dns::protocol::parse_message(forwarded_query);
    require(parsed_forwarded && !parsed_forwarded->header.is_response && parsed_forwarded->questions.size() == 1,
            "the upstream request must remain a valid one-question DNS query");

    auto upstream_response = make_a_response(forwarded_query);
    upstream_response[3] |= std::byte{0x30}; // upstream AD + CD
    require(::sendto(upstream->socket.get(), upstream_response.data(), upstream_response.size(), 0,
                     reinterpret_cast<const sockaddr *>(&worker_address), worker_address_length) == static_cast<ssize_t>(upstream_response.size()),
            "the fake upstream must return its complete DNS response");

    auto client_wire = receive_response(client.get(), "forwarding client");
    auto response    = dns::protocol::parse_message(client_wire);
    require(response && response->header.id == 0xbeef && response->header.is_response &&
                response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::NoError) && response->header.authenticated_data &&
                response->header.checking_disabled,
            "the worker must restore the client transaction ID and transparently forward upstream AD/CD flags");
    require(response->answers.size() == 1 &&
                response->answers.front().rdata == std::vector<std::byte>{std::byte{203}, std::byte{0}, std::byte{113}, std::byte{7}},
            "the forwarded response must preserve the upstream answer bytes");

    worker->request_stop();
    worker_thread.join();
    require(worker->stats().upstream_queries == 1 && worker->stats().upstream_responses == 1 && worker->stats().upstream_timeouts == 0 &&
                worker->stats().responses_sent == 1,
            "the forwarding path must report one successful upstream round trip");
}

void test_oversized_upstream_response_keeps_waiter_pending()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "oversized-upstream fixture must initialize after the suite capability probe");

    Cache::DNS_Cache cache{8, 1};
    auto             upstream_config = blackhole_config(upstream->port);
    upstream_config.query_timeout    = std::chrono::milliseconds{100};
    upstream_config.id_reuse_guard   = std::chrono::milliseconds{100};
    auto worker_result               = dns::server::WorkerLoop::create(0, 0, cache.shard(0), upstream_config);
    require(worker_result.has_value(), "oversized-upstream worker fixture must initialize");
    auto worker = std::move(*worker_result);

    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "oversized-upstream client fixture must be created");
    timeval timeout{1, 0};
    require(::setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "oversized-upstream client receive timeout must be configured");

    CapturedWorkerThread worker_thread{worker.get()};

    send_query(client.get(), worker->bound_port(), make_query(0x5101, dns::protocol::RecordType::A, "oversized.example"));
    auto first_forwarded    = receive_forwarded_query(*upstream, "oversized response followed by a valid response");
    auto valid_response     = make_a_response(first_forwarded.packet);
    auto oversized_response = valid_response;
    oversized_response.resize(dns::protocol::kUpstreamReceiveBufferSize + 1, std::byte{0});
    send_upstream_response(*upstream, first_forwarded, oversized_response);
    send_upstream_response(*upstream, first_forwarded, valid_response);

    auto first_wire = receive_response(client.get(), "valid response after oversized upstream response");
    auto first      = dns::protocol::parse_message(first_wire);
    require(first && first->header.id == 0x5101 && first->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::NoError) &&
                first->answers.size() == 1,
            "an oversized upstream datagram must not complete or remove the pending waiter before a later valid response");

    send_query(client.get(), worker->bound_port(), make_query(0x5102, dns::protocol::RecordType::A, "timeout.example"));
    auto second_forwarded = receive_forwarded_query(*upstream, "oversized response followed by timeout");
    auto second_oversized = make_a_response(second_forwarded.packet);
    second_oversized.resize(dns::protocol::kUpstreamReceiveBufferSize + 1, std::byte{0});
    send_upstream_response(*upstream, second_forwarded, second_oversized);

    auto timeout_wire = receive_response(client.get(), "timeout after oversized upstream response");
    auto timed_out    = dns::protocol::parse_message(timeout_wire);
    require(timed_out && timed_out->header.id == 0x5102 &&
                timed_out->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::ServFail),
            "an oversized upstream datagram must leave the waiter pending until its normal timeout produces SERVFAIL");

    worker->request_stop();
    worker_thread.join();
    require(worker->stats().upstream_queries == 2 && worker->stats().upstream_invalid_responses == 2 && worker->stats().upstream_responses == 1 &&
                worker->stats().upstream_timeouts == 1 && worker->stats().responses_sent == 2,
            "oversized upstream datagrams must be counted invalid without completing either pending waiter");
}

void test_truncated_upstream_response_is_transparent_and_not_cached()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "TC-response fixture must initialize after the suite capability probe");

    Cache::DNS_Cache cache{8, 1};
    auto             upstream_config = blackhole_config(upstream->port);
    upstream_config.query_timeout    = std::chrono::milliseconds{500};
    upstream_config.id_reuse_guard   = std::chrono::milliseconds{500};
    auto worker_result               = dns::server::WorkerLoop::create(0, 0, cache.shard(0), upstream_config);
    require(worker_result.has_value(), "TC-response worker fixture must initialize");
    auto worker = std::move(*worker_result);

    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "TC-response client fixture must be created");
    timeval timeout{1, 0};
    require(::setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "TC-response client receive timeout must be configured");

    CapturedWorkerThread worker_thread{worker.get()};
    for (uint16_t id : {uint16_t{0x5201}, uint16_t{0x5202}})
    {
        send_query(client.get(), worker->bound_port(), make_query(id, dns::protocol::RecordType::A, "truncated.example"));
        auto forwarded = receive_forwarded_query(*upstream, "TC=1 response must not populate the cache");
        auto response  = make_a_response(forwarded.packet);
        response[2] |= std::byte{0x02};
        send_upstream_response(*upstream, forwarded, response);

        auto client_wire = receive_response(client.get(), "transparent TC=1 response");
        auto parsed      = dns::protocol::parse_message(client_wire);
        require(parsed && parsed->header.id == id && parsed->header.truncated && parsed->answers.size() == 1,
                "a valid classic UDP upstream response with TC=1 must be forwarded unchanged without TCP fallback");
    }

    worker->request_stop();
    worker_thread.join();
    require(worker->stats().cache_hits == 0 && worker->stats().cache_misses == 2 && worker->stats().cache_inserts == 0 &&
                worker->stats().upstream_queries == 2 && worker->stats().upstream_responses == 2 && worker->stats().responses_sent == 2,
            "a TC=1 response must not populate the positive cache, so the next query reaches upstream again");
}

void test_cache_reconstruction_overflow_becomes_one_upstream_miss()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "cache-overflow fixture must initialize after the suite capability probe");

    Cache::DNS_Cache cache{8, 1};
    auto             name = dns::protocol::DomainName::from_text("overflow.example");
    require(name.has_value(), "cache-overflow name fixture must be valid");
    std::vector<Cache::IPAddress> addresses;
    addresses.reserve(40);
    for (size_t index = 0; index < 40; ++index)
        addresses.push_back(Cache::IPAddress::v4({192, 0, 2, static_cast<uint8_t>(index + 1)}));
    cache.shard(0).put(
        Cache::CacheKey{*name, static_cast<uint16_t>(dns::protocol::RecordType::A), static_cast<uint16_t>(dns::protocol::RecordClass::IN)},
        std::move(addresses), 60, Cache::Clock::now());

    auto upstream_config           = blackhole_config(upstream->port);
    upstream_config.query_timeout  = std::chrono::milliseconds{500};
    upstream_config.id_reuse_guard = std::chrono::milliseconds{500};
    auto worker_result             = dns::server::WorkerLoop::create(0, 0, cache.shard(0), upstream_config);
    require(worker_result.has_value(), "cache-overflow worker fixture must initialize");
    auto worker = std::move(*worker_result);

    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "cache-overflow client fixture must be created");
    timeval timeout{1, 0};
    require(::setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "cache-overflow client receive timeout must be configured");

    CapturedWorkerThread worker_thread{worker.get()};
    send_query(client.get(), worker->bound_port(), make_query(0x5301, dns::protocol::RecordType::A, "overflow.example"));
    auto forwarded = receive_forwarded_query(*upstream, "cache reconstruction larger than 512 bytes");

    std::array<std::byte, 1> unexpected{};
    errno = 0;
    require(::recvfrom(client.get(), unexpected.data(), unexpected.size(), MSG_DONTWAIT, nullptr, nullptr) == -1 &&
                (errno == EAGAIN || errno == EWOULDBLOCK),
            "an oversized cache reconstruction must not send a partial downstream response before forwarding upstream");

    auto upstream_response = make_a_response(forwarded.packet);
    send_upstream_response(*upstream, forwarded, upstream_response);
    auto client_wire = receive_response(client.get(), "cache reconstruction fallback response");
    auto response    = dns::protocol::parse_message(client_wire);
    require(response && response->header.id == 0x5301 && response->answers.size() == 1,
            "a cache reconstruction overflow must transparently return the single upstream response");

    worker->request_stop();
    worker_thread.join();
    require(worker->stats().cache_hits == 0 && worker->stats().cache_misses == 1 && worker->stats().upstream_queries == 1 &&
                worker->stats().upstream_responses == 1 && worker->stats().responses_sent == 1 && worker->stats().oversized_responses == 0,
            "an unusable cache entry must become exactly one upstream miss without reaching the final send guard");
}

void test_send_response_rejects_oversized_payload()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "send-guard fixture must initialize after the suite capability probe");

    Cache::DNS_Cache cache{1, 1};
    auto             worker_result = dns::server::WorkerLoop::create(0, 0, cache.shard(0), blackhole_config(upstream->port));
    require(worker_result.has_value(), "send-guard worker fixture must initialize");
    auto worker = std::move(*worker_result);

    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "send-guard client fixture must be created");
    sockaddr_in client_address{};
    client_address.sin_family      = AF_INET;
    client_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    client_address.sin_port        = 0;
    require(::bind(client.get(), reinterpret_cast<const sockaddr *>(&client_address), sizeof(client_address)) == 0,
            "send-guard client fixture must bind");
    socklen_t client_length = sizeof(client_address);
    require(::getsockname(client.get(), reinterpret_cast<sockaddr *>(&client_address), &client_length) == 0,
            "send-guard client fixture must expose its address");

    std::vector<std::byte> oversized(dns::protocol::kDownstreamResponseBudget + 1, std::byte{0});
    dns::server::WorkerLoopTestPeer::send_response(*worker, oversized, reinterpret_cast<const sockaddr *>(&client_address), client_length);

    std::array<std::byte, 1> unexpected{};
    errno = 0;
    require(::recvfrom(client.get(), unexpected.data(), unexpected.size(), 0, nullptr, nullptr) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
            "the final send guard must not emit a UDP datagram larger than the downstream response budget");
    require(worker->stats().oversized_responses == 1 && worker->stats().responses_sent == 0 && worker->stats().send_errors == 0,
            "the final send guard must diagnose an oversized response without treating it as a sendto failure");
}

void test_positive_rrsets_are_cached_without_upstream_requery()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "positive-cache upstream fixture must initialize after the suite capability probe");

    Cache::DNS_Cache cache{8, 1};
    auto             upstream_config = blackhole_config(upstream->port);
    upstream_config.query_timeout    = std::chrono::milliseconds{500};
    upstream_config.id_reuse_guard   = std::chrono::milliseconds{500};
    auto worker_result               = dns::server::WorkerLoop::create(0, 0, cache.shard(0), upstream_config);
    require(worker_result.has_value(), "positive-cache worker fixture must initialize");
    auto worker = std::move(*worker_result);

    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "positive-cache client fixture must be created");
    timeval timeout{1, 0};
    require(::setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "positive-cache client receive timeout must be configured");

    CapturedWorkerThread worker_thread{worker.get()};

    send_query(client.get(), worker->bound_port(), make_query(0x1001, dns::protocol::RecordType::A, "Cache.Example."));
    auto first_a_forwarded = receive_forwarded_query(*upstream, "first A cache miss");
    auto first_a_response  = make_a_rrset_response(first_a_forwarded.packet);
    send_upstream_response(*upstream, first_a_forwarded, first_a_response);
    auto first_a_wire = receive_response(client.get(), "first A cache miss");
    auto first_a      = dns::protocol::parse_message(first_a_wire);
    require(first_a && first_a->header.id == 0x1001 && first_a->answers.size() == 2, "the first A request must receive the complete upstream RRset");

    send_query(client.get(), worker->bound_port(), make_query(0x1002, dns::protocol::RecordType::A, "cAcHe.eXaMpLe"));
    auto cached_a_wire = receive_response(client.get(), "cached A response");
    auto cached_a      = dns::protocol::parse_message(cached_a_wire);
    require(cached_a && cached_a->header.id == 0x1002 && cached_a->questions.front().name.to_string() == "cAcHe.eXaMpLe" &&
                cached_a->answers.size() == 2 && cached_a->answers[0].ttl > 0 && cached_a->answers[0].ttl <= 60,
            "an A cache hit must use the current ID/question and return the complete RRset with a remaining TTL");

    send_query(client.get(), worker->bound_port(), make_query(0x1003, dns::protocol::RecordType::A, "cache.example", true));
    auto cd_forwarded = receive_forwarded_query(*upstream, "checking-disabled cache bypass");
    auto cd_response  = make_a_rrset_response(cd_forwarded.packet);
    send_upstream_response(*upstream, cd_forwarded, cd_response);
    auto cd_wire = receive_response(client.get(), "checking-disabled cache bypass");
    auto cd      = dns::protocol::parse_message(cd_wire);
    require(cd && cd->header.id == 0x1003 && cd->header.checking_disabled && cd->answers.size() == 2,
            "a checking-disabled query must bypass an existing validated cache entry and preserve CD upstream");

    send_query(client.get(), worker->bound_port(), make_query(0x1004, dns::protocol::RecordType::A, "cache.example", false, true));
    auto ad_forwarded        = receive_forwarded_query(*upstream, "authenticated-data cache bypass");
    auto parsed_ad_forwarded = dns::protocol::parse_message(ad_forwarded.packet);
    require(parsed_ad_forwarded && parsed_ad_forwarded->header.authenticated_data,
            "an AD-bearing query must reach upstream instead of using an address-only cache entry");
    auto ad_response = make_a_rrset_response(ad_forwarded.packet);
    send_upstream_response(*upstream, ad_forwarded, ad_response);
    auto ad_wire = receive_response(client.get(), "authenticated-data cache bypass");
    auto ad      = dns::protocol::parse_message(ad_wire);
    require(ad && ad->header.id == 0x1004 && ad->answers.size() == 2,
            "an AD-bearing cache bypass must still transparently return the upstream address response");

    send_query(client.get(), worker->bound_port(), make_query(0x2001, dns::protocol::RecordType::AAAA, "cache.example"));
    auto first_aaaa_forwarded = receive_forwarded_query(*upstream, "first AAAA cache miss");
    auto first_aaaa_response  = make_aaaa_rrset_response(first_aaaa_forwarded.packet);
    send_upstream_response(*upstream, first_aaaa_forwarded, first_aaaa_response);
    auto first_aaaa_wire = receive_response(client.get(), "first AAAA cache miss");
    auto first_aaaa      = dns::protocol::parse_message(first_aaaa_wire);
    require(first_aaaa && first_aaaa->header.id == 0x2001 && first_aaaa->answers.size() == 2,
            "an A cache entry must not hide the separate AAAA cache miss");

    send_query(client.get(), worker->bound_port(), make_query(0x2002, dns::protocol::RecordType::AAAA, "CACHE.EXAMPLE."));
    auto cached_aaaa_wire = receive_response(client.get(), "cached AAAA response");
    auto cached_aaaa      = dns::protocol::parse_message(cached_aaaa_wire);
    require(cached_aaaa && cached_aaaa->header.id == 0x2002 && cached_aaaa->answers.size() == 2 && cached_aaaa->answers.front().rdata.size() == 16 &&
                cached_aaaa->answers.front().ttl > 0 && cached_aaaa->answers.front().ttl <= 45,
            "a AAAA cache hit must retain its own address width and TTL");

    worker->request_stop();
    worker_thread.join();
    require(worker->stats().accepted_queries == 6 && worker->stats().cache_misses == 2 && worker->stats().cache_hits == 2 &&
                worker->stats().cache_bypasses == 2 && worker->stats().cache_inserts == 2 && worker->stats().upstream_queries == 4 &&
                worker->stats().upstream_responses == 4 && worker->stats().responses_sent == 6 && worker->stats().internal_errors == 0,
            "two warmed A/AAAA keys must eliminate cacheable round trips while DNSSEC-control queries bypass the address cache");
}

void test_filter_snapshot_precedes_an_existing_cache_entry()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "filter-pipeline upstream fixture must initialize after the suite capability probe");

    DNS       service;
    DNSConfig config;
    config.worker_count            = 1;
    config.runtime_updates_enabled = true;
    config.cache_capacity          = 8;
    config.port                    = 0;
    config.upstream                = blackhole_config(upstream->port);
    require(service.init(config), "runtime-filter service fixture must initialize");
    const auto started = service.start();
    require(static_cast<bool>(started), "runtime-filter service fixture must start after the suite capability probe");

    auto ready_update = service.replace_blocked_domains({});
    require(ready_update && ready_update->generation == 2 && ready_update->rule_count == 0,
            "start must return with the update coordinator ready to process an immediate replacement");

    const auto port = service.bound_port();
    require(port.has_value(), "runtime-filter service must publish its bound port");

    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "filter-pipeline client fixture must be created");
    timeval timeout{1, 0};
    require(::setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "filter-pipeline client receive timeout must be configured");

    send_query(client.get(), *port, make_query(0x3001, dns::protocol::RecordType::A, "WWW.Blocked.Example."));
    auto forwarded         = receive_forwarded_query(*upstream, "cache warm before runtime filter update");
    auto upstream_response = make_a_rrset_response(forwarded.packet);
    send_upstream_response(*upstream, forwarded, upstream_response);
    auto warm_wire = receive_response(client.get(), "cache warm before runtime filter update");
    auto warm      = dns::protocol::parse_message(warm_wire);
    require(warm && warm->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::NoError) && warm->answers.size() == 2,
            "the initial empty snapshot must allow an upstream response to warm the positive cache");

    send_query(client.get(), *port, make_query(0x3002, dns::protocol::RecordType::A, "www.blocked.example"));
    auto cached_wire = receive_response(client.get(), "cache hit before runtime filter update");
    auto cached      = dns::protocol::parse_message(cached_wire);
    require(cached && cached->header.id == 0x3002 && cached->answers.size() == 2,
            "the warmed response must be served from cache before the rule is installed");

    auto update = service.replace_blocked_domains({"blocked.example"});
    require(update && update->generation == 3 && update->rule_count == 1,
            "the update coordinator must publish a complete third-generation blocklist");
    require(service.filter_version() == std::optional{*update}, "the public filter version must identify the committed snapshot");

    send_query(client.get(), *port, make_query(0x3003, dns::protocol::RecordType::A, "www.blocked.example"));
    auto refused_wire = receive_response(client.get(), "REFUSED after filter update");
    auto refused      = dns::protocol::parse_message(refused_wire);
    require(refused && refused->header.id == 0x3003 && refused->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::Refused) &&
                refused->questions.size() == 1 && refused->questions.front().name.to_string() == "www.blocked.example" && refused->answers.empty(),
            "a parent-domain rule must return REFUSED with the current ID/question even when a positive cache entry exists");

    auto invalid = service.replace_blocked_domains({"*.bad.example"});
    require(!invalid && invalid.error().code == dns::server::FilterUpdateErrorCode::BuildFailed,
            "an invalid runtime replacement must report a build failure");
    require(service.filter_version() == std::optional{dns::server::FilterVersion{3, 1}},
            "an invalid runtime replacement must retain the committed generation");

    send_query(client.get(), *port, make_query(0x3004, dns::protocol::RecordType::A, "www.blocked.example"));
    auto rollback_wire = receive_response(client.get(), "REFUSED after invalid filter replacement");
    auto rollback      = dns::protocol::parse_message(rollback_wire);
    require(rollback && rollback->header.id == 0x3004 &&
                rollback->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::Refused) && rollback->answers.empty(),
            "a failed replacement must leave the previous filtering behavior intact");

    auto cleared = service.replace_blocked_domains({});
    require(cleared && cleared->generation == 4 && cleared->rule_count == 0, "an empty replacement must atomically remove all runtime rules");

    send_query(client.get(), *port, make_query(0x3005, dns::protocol::RecordType::A, "www.blocked.example"));
    auto restored_wire = receive_response(client.get(), "cache hit after clearing runtime filter");
    auto restored      = dns::protocol::parse_message(restored_wire);
    require(restored && restored->header.id == 0x3005 &&
                restored->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::NoError) && restored->answers.size() == 2,
            "clearing the filter must expose the existing positive cache entry without another upstream query");

    std::array<std::byte, 64> unexpected_upstream{};
    errno = 0;
    require(::recvfrom(upstream->socket.get(), unexpected_upstream.data(), unexpected_upstream.size(), MSG_DONTWAIT, nullptr, nullptr) == -1 &&
                (errno == EAGAIN || errno == EWOULDBLOCK),
            "cache hits, refused responses, rollback, and rule removal must not emit another upstream packet");

    service.request_stop();
    const auto exit = service.join();
    require(exit.code == DNSServiceExitCode::ExplicitStop, "runtime-filter service shutdown must report ExplicitStop");
}

void test_configured_filter_snapshot_reaches_dns_workers()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "configured-filter upstream fixture must initialize after the suite capability probe");

    DNS       service;
    DNSConfig config;
    config.worker_count            = 1;
    config.runtime_updates_enabled = false;
    config.cache_capacity          = 8;
    config.port                    = 0;
    config.blocked_domains         = {"blocked.example"};
    config.upstream                = blackhole_config(upstream->port);
    require(service.init(config), "configured filter service fixture must initialize");
    const auto started = service.start();
    require(static_cast<bool>(started), "configured-filter service fixture must start after the suite capability probe");

    const auto port = service.bound_port();
    require(port.has_value(), "configured filter service must publish its bound port");
    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "configured filter client fixture must be created");
    timeval timeout{1, 0};
    require(::setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "configured filter client receive timeout must be configured");

    auto response_wire =
        exchange(client.get(), *port, make_query(0x4001, dns::protocol::RecordType::A, "child.Blocked.Example."), "configured parent-domain filter");
    auto response = dns::protocol::parse_message(response_wire);
    require(response && response->header.id == 0x4001 &&
                response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::Refused) &&
                response->questions.front().name.to_string() == "child.Blocked.Example",
            "DNSConfig rules must be published to workers as the initial immutable snapshot");

    std::array<std::byte, 64> unexpected_upstream{};
    errno = 0;
    require(::recvfrom(upstream->socket.get(), unexpected_upstream.data(), unexpected_upstream.size(), MSG_DONTWAIT, nullptr, nullptr) == -1 &&
                (errno == EAGAIN || errno == EWOULDBLOCK),
            "a configured REFUSED decision must not emit an upstream packet");

    service.request_stop();
    const auto exit = service.join();
    require(exit.code == DNSServiceExitCode::ExplicitStop, "configured-filter service shutdown must report ExplicitStop");
}

void test_shutdown_cancels_pending_upstream_query()
{
    auto upstream = make_blackhole_upstream();
    require(upstream.has_value(), "pending-shutdown upstream fixture must initialize after the suite capability probe");

    Cache::DNS_Cache cache{8, 1};
    auto             upstream_config = blackhole_config(upstream->port);
    upstream_config.query_timeout    = std::chrono::seconds{5};
    upstream_config.id_reuse_guard   = std::chrono::seconds{5};
    auto worker_result               = dns::server::WorkerLoop::create(0, 0, cache.shard(0), upstream_config);
    require(worker_result.has_value(), "pending-shutdown worker fixture must initialize");
    auto worker = std::move(*worker_result);

    dns::runtime::UniqueFd client{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    require(static_cast<bool>(client), "pending-shutdown client fixture must be created");
    CapturedWorkerThread worker_thread{worker.get()};
    send_query(client.get(), worker->bound_port(), make_query(0xcafe, dns::protocol::RecordType::A));

    std::array<std::byte, 4096> forwarded{};
    require(::recvfrom(upstream->socket.get(), forwarded.data(), forwarded.size(), 0, nullptr, nullptr) > 0,
            "pending-shutdown query must reach the fake upstream before stop");
    worker->request_stop();
    worker_thread.join();

    require(worker->stats().received_datagrams == 1 && worker->stats().accepted_queries == 1 && worker->stats().upstream_queries == 1 &&
                worker->stats().upstream_cancellations == 1 && worker->stats().responses_sent == 0 && worker->stats().internal_errors == 0,
            "worker shutdown must cancel one pending upstream query without sending or leaking a response");
}

void test_truncated_datagram_decision()
{
    const std::array prefix{std::byte{0x45}, std::byte{0x67}, std::byte{0x01}, std::byte{0x00}};
    auto             decision = dns::server::WorkerLoop::evaluate_datagram(prefix, true);
    require(decision.outcome == dns::server::DatagramOutcome::Truncated, "MSG_TRUNC must bypass normal packet parsing");
    auto response = dns::protocol::parse_message(decision.response);
    require(response && response->header.id == 0x4567 && response->header.response_code == static_cast<uint8_t>(dns::protocol::ResponseCode::FormErr),
            "a truncated query with an ID must produce header-only FORMERR");
}

} // namespace

int main()
{
    const auto socket_capability = dns::test::probe_ipv4_loopback_datagram_io();
    if (!socket_capability.available)
        return dns::test::socket_test_unavailable_exit(socket_capability, "reactor tests");

    test_truncated_datagram_decision();
    test_owned_datagrams_survive_initial_suspend();
    test_udp_reactor_responses();
    test_upstream_response_is_forwarded();
    test_oversized_upstream_response_keeps_waiter_pending();
    test_truncated_upstream_response_is_transparent_and_not_cached();
    test_cache_reconstruction_overflow_becomes_one_upstream_miss();
    test_send_response_rejects_oversized_payload();
    test_positive_rrsets_are_cached_without_upstream_requery();
    test_filter_snapshot_precedes_an_existing_cache_entry();
    test_configured_filter_snapshot_reaches_dns_workers();
    test_shutdown_cancels_pending_upstream_query();
    std::cout << "all reactor tests passed\n";
    return EXIT_SUCCESS;
}
