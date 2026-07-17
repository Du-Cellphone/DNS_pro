#include "DNS_Cache.h"
#include "protocol/DnsMessage.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace
{

using namespace std::chrono_literals;

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "cache test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

dns::protocol::DomainName name(std::string_view text)
{
    auto result = dns::protocol::DomainName::from_text(text);
    require(result.has_value(), "cache test domain must be valid");
    return std::move(*result);
}

Cache::CacheKey key(std::string_view domain, dns::protocol::RecordType type, dns::protocol::RecordClass record_class = dns::protocol::RecordClass::IN)
{
    return Cache::CacheKey{name(domain), static_cast<uint16_t>(type), static_cast<uint16_t>(record_class)};
}

void test_key_partitioning_and_normalization()
{
    Cache::CacheShard shard{8};
    const auto now = Cache::TimePoint{};
    const auto ipv4 = Cache::IPAddress::v4({1, 2, 3, 4});
    const auto ipv6 = Cache::IPAddress::v6({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});

    shard.put(key("WWW.Example.COM.", dns::protocol::RecordType::A), ipv4, 10, now);
    shard.put(key("www.example.com", dns::protocol::RecordType::AAAA), ipv6, 20, now);

    auto a_hit = shard.get(key("www.example.com", dns::protocol::RecordType::A), now);
    auto aaaa_hit = shard.get(key("WWW.EXAMPLE.COM.", dns::protocol::RecordType::AAAA), now);
    require(a_hit && a_hit->addresses == std::vector{ipv4}, "canonical A cache key must hit its own value");
    require(aaaa_hit && aaaa_hit->addresses == std::vector{ipv6}, "AAAA must not overwrite A for the same name");
    require(!shard.get(key("www.example.com", dns::protocol::RecordType::A, dns::protocol::RecordClass::ANY), now),
            "QCLASS must participate in the cache key");
}

void test_ttl_boundaries_and_updates()
{
    Cache::CacheShard shard{2};
    const auto now = Cache::TimePoint{};
    const auto first = Cache::IPAddress::v4({10, 0, 0, 1});
    const auto second = Cache::IPAddress::v4({10, 0, 0, 2});
    const auto cache_key = key("ttl.example", dns::protocol::RecordType::A);

    shard.put(cache_key, first, 10, now);
    auto before_expiry = shard.get(cache_key, now + 9001ms);
    require(before_expiry && before_expiry->remaining_ttl == 1, "remaining TTL must round up a partial final second");
    require(!shard.get(cache_key, now + 10s), "an entry must expire exactly at its deadline");

    shard.put(cache_key, first, 5, now);
    shard.put(cache_key, second, 20, now + 1s);
    require(shard.size() == 1, "updating an existing key must not grow the cache");
    auto updated = shard.get(cache_key, now + 2s);
    require(updated && updated->addresses == std::vector{second} && updated->remaining_ttl == 19,
            "updates must replace value and restart TTL from the new timestamp");

    shard.put(cache_key, first, 0, now + 3s);
    require(!shard.get(cache_key, now + 3s) && shard.size() == 0, "TTL zero must invalidate an existing cache entry");
}

void test_address_rrsets_are_kept_together()
{
    Cache::CacheShard shard{2};
    const auto        now       = Cache::TimePoint{};
    const auto        cache_key = key("rrset.example", dns::protocol::RecordType::A);
    const std::vector addresses{Cache::IPAddress::v4({192, 0, 2, 1}), Cache::IPAddress::v4({192, 0, 2, 2})};

    shard.put(cache_key, addresses, 30, now);
    auto hit = shard.get(cache_key, now + 5s);
    require(hit && hit->addresses == addresses && hit->remaining_ttl == 25,
            "a multi-address RRset must remain ordered and share its conservative TTL");

    shard.put(cache_key, std::vector<Cache::IPAddress>{}, 30, now + 6s);
    require(!shard.get(cache_key, now + 6s), "an empty RRset must invalidate rather than create an unusable cache entry");
}

void test_capacity_and_clock_eviction()
{
    Cache::CacheShard shard{2};
    const auto now = Cache::TimePoint{};
    const auto address = Cache::IPAddress::v4({192, 0, 2, 1});

    for (size_t index = 0; index < 100; ++index)
    {
        auto current = key("entry" + std::to_string(index) + ".example", dns::protocol::RecordType::A);
        shard.put(current, address, 60, now);
        require(shard.size() <= shard.capacity(), "CLOCK eviction must never exceed configured capacity");
        require(shard.get(current, now).has_value(), "the most recently inserted entry must remain reachable");
    }
}

void test_shard_distribution_and_isolation()
{
    Cache::DNS_Cache cache{5, 2};
    require(cache.total_capacity() == 5 && cache.shard_count() == 2, "cache owner must retain configured totals");
    require(cache.shard(0).capacity() == 3 && cache.shard(1).capacity() == 2, "capacity remainder must be distributed without multiplying the total");

    const auto now = Cache::TimePoint{};
    const auto cache_key = key("isolated.example", dns::protocol::RecordType::A);
    cache.shard(0).put(cache_key, Cache::IPAddress::v4({203, 0, 113, 1}), 30, now);
    require(cache.shard(0).get(cache_key, now).has_value(), "the owning shard must see its entry");
    require(!cache.shard(1).get(cache_key, now), "a different shard must not share hidden thread-local state");

    bool bad_index_threw = false;
    try
    {
        static_cast<void>(cache.shard(2));
    }
    catch (const std::out_of_range &)
    {
        bad_index_threw = true;
    }
    require(bad_index_threw, "invalid worker IDs must fail with bounds checking");

    bool zero_shards_threw = false;
    try
    {
        Cache::DNS_Cache invalid{1, 0};
    }
    catch (const std::invalid_argument &)
    {
        zero_shards_threw = true;
    }
    require(zero_shards_threw, "zero shards must be rejected explicitly");

    Cache::CacheShard disabled{0};
    disabled.put(cache_key, Cache::IPAddress::v4({127, 0, 0, 1}), 30, now);
    require(disabled.size() == 0 && !disabled.get(cache_key, now), "zero capacity must behave as a disabled cache");
}

} // namespace

int main()
{
    test_key_partitioning_and_normalization();
    test_ttl_boundaries_and_updates();
    test_address_rrsets_are_kept_together();
    test_capacity_and_clock_eviction();
    test_shard_distribution_and_isolation();
    std::cout << "all cache tests passed\n";
    return EXIT_SUCCESS;
}
