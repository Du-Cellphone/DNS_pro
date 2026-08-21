#include "WorkerLoop.h"
#include "protocol/DnsLimits.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const auto packet = std::as_bytes(std::span{data, size});
    const auto prefix = packet.first(std::min(packet.size(), dns::protocol::kDownstreamReceiveBufferSize));
    const bool truncated = packet.size() > dns::protocol::kDownstreamReceiveBufferSize;
    const auto decision  = dns::server::WorkerLoop::evaluate_datagram(prefix, truncated);

    if (decision.response.size() > dns::protocol::kDownstreamResponseBudget)
        __builtin_trap();

    if (truncated)
    {
        const bool query_prefix = prefix.size() >= 3 && (std::to_integer<uint8_t>(prefix[2]) & 0x80U) == 0;
        if (query_prefix && (decision.outcome != dns::server::DatagramOutcome::Truncated || decision.response.empty()))
            __builtin_trap();
        if (!query_prefix && (decision.outcome != dns::server::DatagramOutcome::Dropped || !decision.response.empty()))
            __builtin_trap();
    }
    return 0;
}
