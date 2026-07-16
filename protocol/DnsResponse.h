#pragma once

#include "common/Expected.h"
#include "protocol/DnsMessage.h"

#include <cstdint>
#include <optional>
#include <span>

namespace dns::protocol
{

enum class ResponseValidationErrorCode
{
    NotAResponse,
    WrongTransactionId,
    WrongOpcode,
    InvalidHeaderFlags,
    WrongQuestionCount,
    QuestionMismatch,
};

struct ResponseValidationError
{
    ResponseValidationErrorCode code;

    bool operator==(const ResponseValidationError &) const = default;
};

using ResponseValidationResult = Expected<void, ResponseValidationError>;

[[nodiscard]] std::optional<uint16_t> transaction_id(std::span<const std::byte> packet) noexcept;

ResponseValidationResult validate_upstream_response(const Message &message, uint16_t expected_transaction_id, uint8_t expected_opcode,
                                                    const Question &expected_question) noexcept;

} // namespace dns::protocol
