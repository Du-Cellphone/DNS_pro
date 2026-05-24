#pragma once
#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <new>
#include <thread>
#include <unordered_map>
#include <vector>
#include "HashUtils.hpp"

namespace Cache
{

inline constexpr size_t TABLE_SIZE     = 1'000'000;
inline constexpr size_t MAX_DOMAIN_LEN = 256;
// inline const size_t                   SHARD_CNT      = std::thread::hardware_concurrency();
// inline constexpr size_t               CACHE_LINE     = std::hardware_destructive_interference_size;
inline constexpr std::chrono::seconds DEFAULT_TTL{300};



using Hash_Table = std::unordered_map<std::string, uint32_t, XXH3_64>;
using TimePoint  = std::chrono::high_resolution_clock::time_point;

struct IPAddress
{
    std::array<uint8_t, 16> ip;
    uint8_t                 len;

    bool operator==(const IPAddress &other) const noexcept { return len == other.len && ip == other.ip; }
};

struct CacheEntry
{
    std::string domain;
    IPAddress   ip;
    TimePoint   expiry;
    bool        chance{true};

    CacheEntry() = default;

    CacheEntry(std::string d, IPAddress i, TimePoint e)
        : domain(d)
        , ip(i)
        , expiry(e)
        , chance(true)
    {
    }

    CacheEntry(const CacheEntry &other)
        : domain(other.domain)
        , ip(other.ip)
        , expiry(other.expiry)
        , chance(other.chance)
    {
    }

    CacheEntry(CacheEntry &&other) noexcept
        : domain(std::move(other.domain))
        , ip(std::move(other.ip))
        , expiry(other.expiry)
        , chance(other.chance)
    {
    }

    CacheEntry &operator=(CacheEntry &&other) noexcept
    {
        if (this != &other)
        {
            domain = std::move(other.domain);
            ip     = std::move(other.ip);
            expiry = other.expiry;
            chance = other.chance;
        }
        return *this;
    }
};

class DNS_Cache final
{
public:
    DNS_Cache(size_t shard_cnt);
    void                     initialize_thread_shard(int id);
    std::optional<IPAddress> get(const std::string &domain, const TimePoint &now);
    void                     put(const std::string &domain, const IPAddress &ip, const TimePoint &now);

private:
    size_t shard_count{0};
    struct CacheShard
    {
        std::vector<CacheEntry> entries;
        size_t                  hand{0};
        Hash_Table              hash_table;

        std::optional<IPAddress> get(const std::string &domain, const TimePoint &now);
        void                     put(const std::string &domain, const IPAddress &ip, const TimePoint &now);
        CacheShard();
    };

    std::vector<std::unique_ptr<CacheShard>> cache_shards; // RAII自动管理，无需手动释放
};


} // namespace Cache
