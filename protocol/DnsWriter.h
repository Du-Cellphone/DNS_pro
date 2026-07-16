#pragma once

#include "protocol/DnsMessage.h"

#include <cstddef>
#include <span>
#include <vector>

namespace dns::protocol
{

enum class WriteErrorCode
{
    MessageTooLarge,
    TooManyQuestions,
    InvalidOpcode,
    InvalidResponseCode,
    InvalidMaximumSize,
    ExpectedQuery,
    MissingTransactionId,
};

struct WriteError
{
    WriteErrorCode code;

    bool operator==(const WriteError &) const = default;
};

using WriteResult = Expected<std::vector<std::byte>, WriteError>;

WriteResult serialize_query(const Header &header, std::span<const Question> questions, size_t maximum_size = 65'535);

Expected<void, WriteError> rewrite_transaction_id(std::span<std::byte> packet, uint16_t transaction_id) noexcept;

WriteResult make_error_response(const Message &request,
                                ResponseCode  response_code,
                                bool          recursion_available = true,
                                size_t        maximum_size = 65'535);

WriteResult make_format_error_response(std::span<const std::byte> malformed_request,
                                       bool                       recursion_available = true,
                                       size_t                     maximum_size = 65'535);

} // namespace dns::protocol
