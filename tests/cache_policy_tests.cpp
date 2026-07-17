#include "CachePolicy.h"
#include "protocol/DomainName.h"

#include <array>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "cache policy test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

dns::protocol::DomainName name(std::string_view text)
{
    auto result = dns::protocol::DomainName::from_text(text);
    require(result.has_value(), "fixture domain must be valid");
    return std::move(*result);
}

dns::protocol::Question question(std::string_view domain, dns::protocol::RecordType type)
{
    return dns::protocol::Question{name(domain), static_cast<uint16_t>(type), static_cast<uint16_t>(dns::protocol::RecordClass::IN)};
}

dns::protocol::ResourceRecord address_record(const dns::protocol::Question &query,
                                             uint32_t                       ttl,
                                             std::initializer_list<uint8_t> bytes)
{
    dns::protocol::ResourceRecord answer;
    answer.name         = query.name;
    answer.type         = query.type;
    answer.record_class = query.question_class;
    answer.ttl          = ttl;
    for (uint8_t value : bytes)
        answer.rdata.push_back(static_cast<std::byte>(value));
    return answer;
}

dns::protocol::Message direct_a_response()
{
    dns::protocol::Message response;
    response.header.is_response          = true;
    response.header.recursion_available  = true;
    response.header.response_code        = static_cast<uint8_t>(dns::protocol::ResponseCode::NoError);
    response.questions.push_back(question("Example.COM", dns::protocol::RecordType::A));
    response.answers.push_back(address_record(response.questions.front(), 60, {192, 0, 2, 1}));
    response.answers.push_back(address_record(response.questions.front(), 25, {192, 0, 2, 2}));
    return response;
}

void test_direct_rrset_admission()
{
    auto response  = direct_a_response();
    auto cacheable = dns::server::cacheable_address_set(response, question("example.com.", dns::protocol::RecordType::A));
    require(cacheable && cacheable->ttl == 25 && cacheable->addresses.size() == 2,
            "all direct A records must be cached together using the minimum RRset TTL");
    require(cacheable->addresses[0] == Cache::IPAddress::v4({192, 0, 2, 1}) &&
                cacheable->addresses[1] == Cache::IPAddress::v4({192, 0, 2, 2}),
            "RRset admission must preserve upstream address order");

    dns::protocol::Message aaaa;
    aaaa.header.is_response         = true;
    aaaa.header.recursion_available = true;
    aaaa.questions.push_back(question("ipv6.example", dns::protocol::RecordType::AAAA));
    aaaa.answers.push_back(address_record(aaaa.questions.front(), 40, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}));
    auto ipv6 = dns::server::cacheable_address_set(aaaa, aaaa.questions.front());
    require(ipv6 && ipv6->addresses.size() == 1 && ipv6->addresses.front().is_v6(), "a direct AAAA response must be cacheable");
}

void test_non_positive_responses_are_rejected()
{
    const auto expected = question("example.com", dns::protocol::RecordType::A);

    auto response = direct_a_response();
    response.header.response_code = static_cast<uint8_t>(dns::protocol::ResponseCode::NxDomain);
    require(!dns::server::cacheable_address_set(response, expected), "NXDOMAIN must never enter the positive cache");

    response = direct_a_response();
    response.header.truncated = true;
    require(!dns::server::cacheable_address_set(response, expected), "a truncated UDP response must not be cached");

    response = direct_a_response();
    response.answers.clear();
    require(!dns::server::cacheable_address_set(response, expected), "NODATA must not become a positive cache entry");

    response = direct_a_response();
    response.answers.front().ttl = 0;
    require(!dns::server::cacheable_address_set(response, expected), "a zero-TTL member must make the whole RRset uncacheable");
}

void test_only_losslessly_reproducible_rrsets_are_admitted()
{
    const auto expected = question("example.com", dns::protocol::RecordType::A);

    auto response = direct_a_response();
    response.answers.front().name = name("alias.example.com");
    require(!dns::server::cacheable_address_set(response, expected), "a terminal address behind a CNAME owner must not be rewritten as a direct answer");

    response = direct_a_response();
    response.answers.front().type = static_cast<uint16_t>(dns::protocol::RecordType::CNAME);
    require(!dns::server::cacheable_address_set(response, expected), "CNAME answer chains are outside the address-only cache model");

    response = direct_a_response();
    response.answers.front().rdata.pop_back();
    require(!dns::server::cacheable_address_set(response, expected), "malformed address lengths must not enter the cache");

    response = direct_a_response();
    response.authorities.emplace_back();
    require(!dns::server::cacheable_address_set(response, expected), "authority data that the cache writer would drop must bypass caching");

    response = direct_a_response();
    response.additionals.emplace_back();
    require(!dns::server::cacheable_address_set(response, expected), "additional data that the cache writer would drop must bypass caching");

    response = direct_a_response();
    require(!dns::server::cacheable_address_set(response, question("other.example", dns::protocol::RecordType::A)),
            "a response for another canonical question must not poison this cache key");
}

} // namespace

int main()
{
    test_direct_rrset_admission();
    test_non_positive_responses_are_rejected();
    test_only_losslessly_reproducible_rrsets_are_admitted();
    std::cout << "all cache policy tests passed\n";
    return EXIT_SUCCESS;
}
