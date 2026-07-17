#include "DNS_Cache.h"

#include "HashUtils.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace Cache
{

IPAddress IPAddress::v4(std::array<uint8_t, 4> value) noexcept
{
    IPAddress result;
    std::copy(value.begin(), value.end(), result.bytes.begin());
    result.family = AF_INET;
    return result;
}

IPAddress IPAddress::v6(std::array<uint8_t, 16> value) noexcept
{
    IPAddress result;
    result.bytes  = value;
    result.family = AF_INET6;
    return result;
}

size_t CacheKeyHash::operator()(const CacheKey &key) const noexcept
{
    uint64_t hash = xxH3_64bits(key.qname);
    hash ^= static_cast<uint64_t>(key.qtype) << 32U;
    hash ^= static_cast<uint64_t>(key.qclass) << 48U;
    hash ^= hash >> 30U;
    hash *= 0xbf58476d1ce4e5b9ULL;
    hash ^= hash >> 27U;
    return static_cast<size_t>(hash);
}

CacheShard::CacheShard(size_t capacity)
    : capacity_(capacity)
{
    entries_.reserve(capacity_);
    index_.max_load_factor(0.75F);
    index_.reserve(capacity_);
}

std::optional<CacheHit> CacheShard::get(const CacheKey &key, TimePoint now)
{
    const auto found = index_.find(key);
    if (found == index_.end())
        return std::nullopt;

    std::optional<CacheEntry> &slot = entries_[found->second];
    if (!slot || now >= slot->expiry)
    {
        index_.erase(found);
        slot.reset();
        return std::nullopt;
    }

    slot->chance                 = true;
    const auto remaining         = std::chrono::ceil<std::chrono::seconds>(slot->expiry - now).count();
    const auto bounded_remaining = std::clamp<int64_t>(remaining, 1, std::numeric_limits<uint32_t>::max());
    return CacheHit{slot->addresses, static_cast<uint32_t>(bounded_remaining)};
}

void CacheShard::put(CacheKey key, std::vector<IPAddress> addresses, uint32_t ttl_seconds, TimePoint now)
{
    if (capacity_ == 0)
        return;

    const auto existing = index_.find(key);
    if (ttl_seconds == 0 || addresses.empty())
    {
        if (existing != index_.end())
        {
            entries_[existing->second].reset();
            index_.erase(existing);
        }
        return;
    }

    const TimePoint expiry = now + std::chrono::seconds{ttl_seconds};
    if (existing != index_.end())
    {
        CacheEntry &entry = *entries_[existing->second];
        entry.addresses   = std::move(addresses);
        entry.expiry      = expiry;
        entry.chance      = true;
        return;
    }

    if (entries_.size() < capacity_)
    {
        const size_t slot_index = entries_.size();
        entries_.emplace_back(CacheEntry{std::move(key), std::move(addresses), expiry, true});
        index_.emplace(entries_.back()->key, slot_index);
        return;
    }

    while (true)
    {
        std::optional<CacheEntry> &slot = entries_[hand_];
        if (!slot || now >= slot->expiry || !slot->chance)
        {
            replace_slot(hand_, std::move(key), std::move(addresses), expiry);
            hand_ = (hand_ + 1) % capacity_;
            return;
        }

        slot->chance = false;
        hand_        = (hand_ + 1) % capacity_;
    }
}

void CacheShard::put(CacheKey key, IPAddress address, uint32_t ttl_seconds, TimePoint now)
{
    if (capacity_ == 0)
        return;

    std::vector<IPAddress> addresses;
    addresses.push_back(address);
    put(std::move(key), std::move(addresses), ttl_seconds, now);
}

void CacheShard::replace_slot(size_t slot_index, CacheKey key, std::vector<IPAddress> addresses, TimePoint expiry)
{
    std::optional<CacheEntry> &slot = entries_[slot_index];
    if (slot)
        index_.erase(slot->key);

    slot.emplace(CacheEntry{std::move(key), std::move(addresses), expiry, true});
    index_.emplace(slot->key, slot_index);
}

DNS_Cache::DNS_Cache(size_t total_capacity, size_t shard_count)
    : total_capacity_(total_capacity)
{
    if (shard_count == 0)
        throw std::invalid_argument("DNS_Cache requires at least one shard");

    shards_.reserve(shard_count);
    const size_t base_capacity = total_capacity / shard_count;
    const size_t remainder     = total_capacity % shard_count;
    for (size_t index = 0; index < shard_count; ++index)
        shards_.emplace_back(base_capacity + (index < remainder ? 1 : 0));
}

CacheShard &DNS_Cache::shard(size_t worker_id)
{
    return shards_.at(worker_id);
}

const CacheShard &DNS_Cache::shard(size_t worker_id) const
{
    return shards_.at(worker_id);
}

} // namespace Cache
