#include "protocol/DnsResponse.h"

namespace dns::protocol
{
namespace
{

Unexpected<ResponseValidationError> validation_failure(ResponseValidationErrorCode code)
{
    return dns::unexpected(ResponseValidationError{code});
}

} // namespace

std::optional<uint16_t> transaction_id(std::span<const std::byte> packet) noexcept
{
    if (packet.size() < sizeof(uint16_t))
        return std::nullopt;
    return static_cast<uint16_t>((static_cast<uint16_t>(std::to_integer<uint8_t>(packet[0])) << 8U) |
                                 static_cast<uint16_t>(std::to_integer<uint8_t>(packet[1])));
}

ResponseValidationResult validate_upstream_response(const Message &message, uint16_t expected_transaction_id, uint8_t expected_opcode,
                                                    const Question &expected_question) noexcept
{
    if (!message.header.is_response)
        return validation_failure(ResponseValidationErrorCode::NotAResponse);
    if (message.header.id != expected_transaction_id)
        return validation_failure(ResponseValidationErrorCode::WrongTransactionId);
    if (message.header.opcode != expected_opcode)
        return validation_failure(ResponseValidationErrorCode::WrongOpcode);
    if (message.header.reserved_z)
        return validation_failure(ResponseValidationErrorCode::InvalidHeaderFlags);
    if (message.questions.size() != 1)
        return validation_failure(ResponseValidationErrorCode::WrongQuestionCount);
    if (!(message.questions.front() == expected_question))
        return validation_failure(ResponseValidationErrorCode::QuestionMismatch);
    return {};
}

} // namespace dns::protocol
