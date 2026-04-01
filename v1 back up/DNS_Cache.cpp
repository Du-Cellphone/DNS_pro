#include "DNS_Cache.h"
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>

DNS_Cache::DNS_Cache()
{
    for (size_t i = 0; i < SHARD_CNT; ++i)
    {
        cache_shards.emplace_back(new CacheShard);
    }
}

std::optional<std::vector<unsigned char>> DNS_Cache::get(const std::string &domain, const TimePoint &now)
{
    size_t shard_id = get_shard_id(domain);
    return cache_shards[shard_id]->get(domain, now);
}

void DNS_Cache::put(const std::string &domain, const std::vector<unsigned char> &ip, const TimePoint &now)
{
    size_t shard_id = get_shard_id(domain);
    cache_shards[shard_id]->put(domain, ip, now);
}

size_t DNS_Cache::get_shard_id(const std::string &domain) const
{
    DomainHash hash;
    return hash(domain) % SHARD_CNT;
}

std::optional<std::vector<unsigned char>> DNS_Cache::CacheShard::get(const std::string &domain, const TimePoint &now)
{
    // std::shared_lock<std::shared_mutex> lock(smtx);
    lock();

    Hash_Table::iterator it = hash_table.find(domain);
    if (it == hash_table.end() || now > entries[it->second].expiry)
    {
        unlock();
        return std::nullopt;
    }
    CacheEntry &entry = entries[it->second];
    entry.chance      = true;
    unlock();
    return entry.ip;
}

void DNS_Cache::CacheShard::put(const std::string &domain, const std::vector<unsigned char> &ip, const TimePoint &now)
{
    // std::lock_guard<std::shared_mutex> lock(smtx);
    lock();
    Hash_Table::iterator it = hash_table.find(domain);
    if (it != hash_table.end()) // 已在缓存中，则更新一下
    {
        CacheEntry &entry = entries[it->second];
        entry.ip          = ip;
        entry.ip_len      = ip.size(); // TODO
        entry.expiry      = now + std::chrono::seconds(300);
        entry.chance      = true;
        unlock();
        return;
    }



    if (entries.size() < entries.capacity()) // entries未满
    {
        hash_table[domain] = entries.size();
        entries.emplace_back(domain, ip, ip.size(), now + std::chrono::seconds(300));
        unlock();
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
            current.ip_len = ip.size();
            current.expiry = now + std::chrono::seconds(300);
            current.chance = true;

            hand = (hand + 1) % entries.size();
            unlock();
            return;
        }
        else
        {
            current.chance = false;
            hand           = (hand + 1) % entries.size();
        }
    }
    unlock();
}