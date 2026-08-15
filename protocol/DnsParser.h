#pragma once

#include "common/Expected.h"
#include "protocol/DnsMessage.h"

#include <cstddef>
#include <span>

namespace dns::protocol
{

enum class ParseErrorCode
{
    PacketTooLarge,
    UnexpectedEnd,
    TooManyQuestions,
    TooManyRecords,
    InvalidLabelType,
    EmptyLabel,
    LabelTooLong,
    NameTooLong,
    TruncatedCompressionPointer,
    CompressionPointerOutOfBounds,
    CompressionPointerIntoHeader,
    ForwardCompressionPointer,
    CompressionPointerLoop,
    TooManyCompressionPointers,
    InvalidRdata,
    TrailingData,
};

struct ParseError
{
    ParseErrorCode code;
    size_t         offset{0};

    bool operator==(const ParseError &) const = default;
};

struct ParseLimits
{
    size_t maximum_packet_size{65'535};
    size_t maximum_questions{16};
    size_t maximum_records_per_section{4'096};
    size_t maximum_total_records{4'096};
    size_t maximum_compression_pointers{32};
    bool   require_backward_pointers{true};
    bool   reject_trailing_data{true};
};

using ParseResult = std::expected<Message, ParseError>;

ParseResult parse_message(std::span<const std::byte> packet, const ParseLimits &limits = {});

} // namespace dns::protocol
