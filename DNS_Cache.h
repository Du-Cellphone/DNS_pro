#pragma once

#include "protocol/DomainName.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <unordered_map>
#include <vector>

namespace Cache
{

inline constexpr size_t DEFAULT_TOTAL_CAPACITY = 1'000'000;

using Clock     = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

struct IPAddress
{
    std::array<uint8_t, 16> bytes{};
    sa_family_t             family{AF_UNSPEC};

    IPAddress() = default;

    static IPAddress v4(std::array<uint8_t, 4> value) noexcept;
    static IPAddress v6(std::array<uint8_t, 16> value) noexcept;

    [[nodiscard]] bool is_v4() const noexcept { return family == AF_INET; }
    [[nodiscard]] bool is_v6() const noexcept { return family == AF_INET6; }

    bool operator==(const IPAddress &) const = default;
};

struct CacheKey
{
    std::string qname;
    uint16_t    qtype{0};
    uint16_t    qclass{0};

    CacheKey() = default;
    CacheKey(const dns::protocol::DomainName &name, uint16_t type, uint16_t record_class)
        : qname(name.canonical_key())
        , qtype(type)
        , qclass(record_class)
    {
    }

    bool operator==(const CacheKey &) const = default;
};

struct CacheKeyHash
{
    size_t operator()(const CacheKey &key) const noexcept;
};

struct CacheHit
{
    std::vector<IPAddress> addresses;
    uint32_t               remaining_ttl{0};
};

class CacheShard final
{
public:
    explicit CacheShard(size_t capacity);
    CacheShard(CacheShard &&) noexcept            = default;
    CacheShard &operator=(CacheShard &&) noexcept = default;
    CacheShard(const CacheShard &)                = delete;
    CacheShard &operator=(const CacheShard &)     = delete;

    [[nodiscard]] std::optional<CacheHit> get(const CacheKey &key, TimePoint now);
    void put(CacheKey key, std::vector<IPAddress> addresses, uint32_t ttl_seconds, TimePoint now);
    void put(CacheKey key, IPAddress address, uint32_t ttl_seconds, TimePoint now);

    [[nodiscard]] size_t size() const noexcept { return index_.size(); }
    [[nodiscard]] size_t capacity() const noexcept { return capacity_; }

private:
    struct CacheEntry
    {
        CacheKey              key;
        std::vector<IPAddress> addresses;
        TimePoint             expiry;
        bool                  chance{true};
    };

    using Index = std::unordered_map<CacheKey, size_t, CacheKeyHash>;

    void replace_slot(size_t slot_index, CacheKey key, std::vector<IPAddress> addresses, TimePoint expiry);

    size_t                                 capacity_{0};
    size_t                                 hand_{0};
    std::vector<std::optional<CacheEntry>> entries_;
    Index                                  index_;
};

class DNS_Cache final
{
public:
    DNS_Cache(size_t total_capacity, size_t shard_count);

    [[nodiscard]] CacheShard       &shard(size_t worker_id);
    [[nodiscard]] const CacheShard &shard(size_t worker_id) const;
    [[nodiscard]] size_t            shard_count() const noexcept { return shards_.size(); }
    [[nodiscard]] size_t            total_capacity() const noexcept { return total_capacity_; }

private:
    size_t                  total_capacity_{0};
    std::vector<CacheShard> shards_;
};

} // namespace Cache
