#include "protocol/DnsParser.h"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const auto bytes = std::as_bytes(std::span{data, size});
    static_cast<void>(dns::protocol::parse_message(bytes));
    return 0;
}
