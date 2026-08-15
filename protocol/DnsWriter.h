#pragma once

#include "common/Expected.h"
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
    TooManyAnswers,
    InvalidOpcode,
    InvalidResponseCode,
    InvalidMaximumSize,
    ExpectedQuery,
    MissingTransactionId,
    WrongQuestionCount,
    UnsupportedAddressType,
    InvalidAddressLength,
    MissingAnswers,
};

struct WriteError
{
    WriteErrorCode code;

    bool operator==(const WriteError &) const = default;
};

using WriteResult = std::expected<std::vector<std::byte>, WriteError>;

WriteResult serialize_query(const Header &header, std::span<const Question> questions, size_t maximum_size = 65'535);

std::expected<void, WriteError> rewrite_transaction_id(std::span<std::byte> packet, uint16_t transaction_id) noexcept;

WriteResult make_error_response(const Message &request,
                                ResponseCode  response_code,
                                bool          recursion_available = true,
                                size_t        maximum_size = 65'535);

WriteResult make_format_error_response(std::span<const std::byte> malformed_request,
                                       bool                       recursion_available = true,
                                       size_t                     maximum_size = 65'535);

struct AddressAnswerView
{
    std::span<const std::byte> bytes;
};

WriteResult make_address_response(const Message                         &request,
                                  std::span<const AddressAnswerView>     answers,
                                  uint32_t                               ttl,
                                  bool                                   recursion_available = true,
                                  size_t                                 maximum_size = 65'535);

} // namespace dns::protocol
