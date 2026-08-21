#pragma once

#include <cstddef>

namespace dns::protocol
{

// DNS_PRO intentionally implements classic UDP DNS without EDNS. Keep the
// protocol parser generic; these aliases describe limits at service transport
// boundaries instead of a DNS wire-format limit.
inline constexpr size_t kClassicDnsUdpPayloadLimit = 512;

inline constexpr size_t kDownstreamReceiveBufferSize = kClassicDnsUdpPayloadLimit;
inline constexpr size_t kUpstreamQueryBudget          = kClassicDnsUdpPayloadLimit;
inline constexpr size_t kUpstreamReceiveBufferSize    = kClassicDnsUdpPayloadLimit;
inline constexpr size_t kDownstreamResponseBudget     = kClassicDnsUdpPayloadLimit;

} // namespace dns::protocol
