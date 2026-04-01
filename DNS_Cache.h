#pragma once
#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <nmmintrin.h>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <new>
#include <thread>
#include <unordered_map>
#include <vector>
#include <windows.h>
#include "SpinLock.hpp"


inline constexpr size_t               TABLE_SIZE     = 1'000'000;
inline constexpr size_t               MAX_DOMAIN_LEN = 256;
inline const size_t                   SHARD_CNT      = std::thread::hardware_concurrency();
inline constexpr size_t               CACHE_LINE     = std::hardware_destructive_interference_size;
inline constexpr std::chrono::seconds DEFAULT_TTL{300};

struct DomainHash
{
    size_t operator()(const std::string &d) const
    {
        const char *data = d.data();
        size_t      len  = d.size();

        uint64_t crc = 0;

        while (len >= 8)
        {
            crc = _mm_crc32_u64(crc, *reinterpret_cast<const uint64_t *>(data));
            data += 8;
            len -= 8;
        }

        while (len >= 4)
        {
            crc = _mm_crc32_u32(crc, *reinterpret_cast<const uint32_t *>(data));
            data += 4;
            len -= 4;
        }

        while (len >= 2)
        {
            crc = _mm_crc32_u16(crc, *reinterpret_cast<const uint16_t *>(data));
            data += 2;
            len -= 2;
        }

        if (len >= 1)
            crc = _mm_crc32_u8(crc, *reinterpret_cast<const uint8_t *>(data));

        return static_cast<size_t>(crc);
    }
};

using Hash_Table = std::unordered_map<std::string, uint32_t, DomainHash>;
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
    size_t      ip_len;
    TimePoint   expiry;
    bool        chance{true};

    CacheEntry() = default;

    CacheEntry(std::string d, IPAddress i, size_t i_l, TimePoint e)
        : domain(std::move(d))
        , ip(std::move(i))
        , ip_len(i_l)
        , expiry(e)
        , chance(true)
    {
        // chance.store(true);
    }

    CacheEntry(const CacheEntry &other)
        : domain(other.domain)
        , ip(other.ip)
        , ip_len(other.ip_len)
        , expiry(other.expiry)
        , chance(other.chance)
    {
        // chance.store(other.chance.load());
    }

    CacheEntry(CacheEntry &&other) noexcept
        : domain(std::move(other.domain))
        , ip(std::move(other.ip))
        , ip_len(other.ip_len)
        , expiry(other.expiry)
        , chance(other.chance)
    {
        // chance.store(other.chance.load());
    }

    CacheEntry &operator=(CacheEntry &&other) noexcept
    {
        if (this != &other)
        {
            domain = std::move(other.domain);
            ip     = std::move(other.ip);
            ip_len = other.ip_len;
            expiry = other.expiry;
            chance = other.chance;
            // chance.store(other.chance.load());
        }
        return *this;
    }
};

class DNS_Cache
{
public:
    DNS_Cache();
    std::optional<IPAddress> get(const std::string &domain, const TimePoint &now);
    void                     put(const std::string &domain, const IPAddress &ip, const TimePoint &now);

private:
    struct CacheShard
    {
        SpinLock slock;

        std::vector<CacheEntry> entries;
        size_t                  hand{0};
        Hash_Table              hash_table;

        std::optional<IPAddress> get(const std::string &domain, const TimePoint &now);
        void                     put(const std::string &domain, const IPAddress &ip, const TimePoint &now);

        CacheShard()
        {
            hash_table.reserve(TABLE_SIZE / SHARD_CNT);
            entries.reserve(TABLE_SIZE / SHARD_CNT);
        }
    };


    size_t get_shard_id(const std::string &domain) const;

    std::vector<std::unique_ptr<CacheShard>> cache_shards;
};