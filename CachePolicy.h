#pragma once

#include "DNS_Cache.h"
#include "protocol/DnsMessage.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace dns::server
{

struct CacheableAddressSet
{
    std::vector<Cache::IPAddress> addresses;
    uint32_t                      ttl{0};
};

// Only direct A/AAAA RRsets that can be reproduced without CNAME or
// authority/additional data are admitted. Other valid responses are still
// forwarded unchanged; they simply bypass the MVP positive cache.
std::optional<CacheableAddressSet> cacheable_address_set(const protocol::Message  &response,
                                                         const protocol::Question &expected_question);

} // namespace dns::server
