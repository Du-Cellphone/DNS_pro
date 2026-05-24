#include "DNS_Cache.h"
#include <cstddef>
#include <memory>
#include <optional>
#include <vector>

namespace Cache
{


thread_local int my_shard_id = -1;

DNS_Cache::DNS_Cache(size_t shard_cnt)
{
    shard_count = shard_cnt;
    for (size_t i = 0; i < shard_count; ++i)
    {
        cache_shards.emplace_back(new CacheShard);
    }
}


void DNS_Cache::initialize_thread_shard(int id)
{
    my_shard_id = id % shard_count;
}


std::optional<IPAddress> DNS_Cache::get(const std::string &domain, const TimePoint &now)
{
    return cache_shards[my_shard_id]->get(domain, now);
}


void DNS_Cache::put(const std::string &domain, const IPAddress &ip, const TimePoint &now)
{
    cache_shards[my_shard_id]->put(domain, ip, now);
}


std::optional<IPAddress> DNS_Cache::CacheShard::get(const std::string &domain, const TimePoint &now)
{

    Hash_Table::iterator it = hash_table.find(domain);
    if (it == hash_table.end() || now > entries[it->second].expiry) // TODO 如果请求TYPE_A但缓存里是TYPE_AAAA，这样的情况目前是无法命中的
        return std::nullopt;

    CacheEntry &entry = entries[it->second];
    entry.chance      = true;
    return entry.ip;
}


void DNS_Cache::CacheShard::put(const std::string &domain, const IPAddress &ip, const TimePoint &now)
{
    Hash_Table::iterator it = hash_table.find(domain);
    if (it != hash_table.end()) // 已在缓存中，则更新一下
    {
        CacheEntry &entry = entries[it->second];
        entry.ip          = ip;
        entry.expiry      = now + DEFAULT_TTL;
        entry.chance      = true;
        return;
    }

    if (entries.size() < entries.capacity()) // entries未满
    {
        hash_table[domain] = entries.size();
        entries.emplace_back(domain, ip, now + DEFAULT_TTL);
        return;
    }

    while (true)
    {
        CacheEntry &current    = entries[hand];
        bool        has_chance = current.chance;
        bool        is_expired = now > current.expiry;

        if (!has_chance || is_expired)
        {
            hash_table.erase(current.domain);
            hash_table[domain] = hand;

            current.domain = domain;
            current.ip     = ip;
            current.expiry = now + DEFAULT_TTL;
            current.chance = true;

            hand = (hand + 1) % entries.size();
            return;
        }
        else
        {
            current.chance = false;
            hand           = (hand + 1) % entries.size();
        }
    }
}


DNS_Cache::CacheShard::CacheShard()
{
    hash_table.reserve(TABLE_SIZE / 0.75); // 负载因子0.75
    entries.reserve(TABLE_SIZE);
}


} // namespace Cache
