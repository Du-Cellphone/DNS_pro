#include "protocol/DnsWriter.h"

#include "protocol/Wire.h"

#include <cstdint>
#include <limits>

namespace dns::protocol
{
namespace
{

Unexpected<WriteError> write_failure(WriteErrorCode code)
{
    return dns::unexpected(WriteError{code});
}

Expected<uint16_t, WriteError> encode_flags(const Header &header)
{
    if (header.opcode > 0x0fU)
        return write_failure(WriteErrorCode::InvalidOpcode);
    if (header.response_code > 0x0fU)
        return write_failure(WriteErrorCode::InvalidResponseCode);

    uint16_t flags = 0;
    flags |= header.is_response ? 0x8000U : 0U;
    flags |= static_cast<uint16_t>(header.opcode) << 11U;
    flags |= header.authoritative_answer ? 0x0400U : 0U;
    flags |= header.truncated ? 0x0200U : 0U;
    flags |= header.recursion_desired ? 0x0100U : 0U;
    flags |= header.recursion_available ? 0x0080U : 0U;
    flags |= header.reserved_z ? 0x0040U : 0U;
    flags |= header.authenticated_data ? 0x0020U : 0U;
    flags |= header.checking_disabled ? 0x0010U : 0U;
    flags |= static_cast<uint16_t>(header.response_code);
    return flags;
}

bool write_name(detail::WireWriter &writer, const DomainName &name)
{
    for (const std::string &label : name.labels())
    {
        if (!writer.write_u8(static_cast<uint8_t>(label.size())))
            return false;
        const auto bytes = std::as_bytes(std::span{label.data(), label.size()});
        if (!writer.write_bytes(bytes))
            return false;
    }
    return writer.write_u8(0);
}

WriteResult write_question_message(const Header &header, std::span<const Question> questions, size_t maximum_size)
{
    if (maximum_size > 65'535)
        return write_failure(WriteErrorCode::InvalidMaximumSize);
    if (questions.size() > std::numeric_limits<uint16_t>::max())
        return write_failure(WriteErrorCode::TooManyQuestions);

    auto flags = encode_flags(header);
    if (!flags)
        return dns::unexpected(flags.error());

    detail::WireWriter writer{maximum_size};
    if (!writer.write_u16(header.id) || !writer.write_u16(*flags) || !writer.write_u16(static_cast<uint16_t>(questions.size())) ||
        !writer.write_u16(0) || !writer.write_u16(0) || !writer.write_u16(0))
        return write_failure(WriteErrorCode::MessageTooLarge);

    for (const Question &question : questions)
    {
        if (!write_name(writer, question.name) || !writer.write_u16(question.type) || !writer.write_u16(question.question_class))
            return write_failure(WriteErrorCode::MessageTooLarge);
    }

    return std::move(writer).take();
}

} // namespace

WriteResult serialize_query(const Header &header, std::span<const Question> questions, size_t maximum_size)
{
    if (header.is_response)
        return write_failure(WriteErrorCode::ExpectedQuery);

    Header query_header = header;
    query_header.authoritative_answer = false;
    query_header.truncated = false;
    query_header.recursion_available = false;
    query_header.response_code = static_cast<uint8_t>(ResponseCode::NoError);
    return write_question_message(query_header, questions, maximum_size);
}

Expected<void, WriteError> rewrite_transaction_id(std::span<std::byte> packet, uint16_t transaction_id) noexcept
{
    if (packet.size() < sizeof(transaction_id))
        return write_failure(WriteErrorCode::MissingTransactionId);

    packet[0] = static_cast<std::byte>((transaction_id >> 8U) & 0xffU);
    packet[1] = static_cast<std::byte>(transaction_id & 0xffU);
    return {};
}

WriteResult make_error_response(const Message &request, ResponseCode response_code, bool recursion_available, size_t maximum_size)
{
    if (request.header.is_response)
        return write_failure(WriteErrorCode::ExpectedQuery);

    Header response_header;
    response_header.id = request.header.id;
    response_header.is_response = true;
    response_header.opcode = request.header.opcode;
    response_header.recursion_desired = request.header.recursion_desired;
    response_header.recursion_available = recursion_available;
    response_header.checking_disabled = request.header.checking_disabled;
    response_header.response_code = static_cast<uint8_t>(response_code);
    return write_question_message(response_header, request.questions, maximum_size);
}

WriteResult make_format_error_response(std::span<const std::byte> malformed_request, bool recursion_available, size_t maximum_size)
{
    if (malformed_request.size() < sizeof(uint16_t))
        return write_failure(WriteErrorCode::MissingTransactionId);

    Header response_header;
    response_header.id = static_cast<uint16_t>((static_cast<uint16_t>(std::to_integer<uint8_t>(malformed_request[0])) << 8U) |
                                               static_cast<uint16_t>(std::to_integer<uint8_t>(malformed_request[1])));
    response_header.is_response = true;
    response_header.recursion_available = recursion_available;
    response_header.response_code = static_cast<uint8_t>(ResponseCode::FormErr);

    if (malformed_request.size() >= 3)
    {
        const uint8_t high_flags = std::to_integer<uint8_t>(malformed_request[2]);
        if ((high_flags & 0x80U) != 0)
            return write_failure(WriteErrorCode::ExpectedQuery);
        response_header.opcode = static_cast<uint8_t>((high_flags >> 3U) & 0x0fU);
        response_header.recursion_desired = (high_flags & 0x01U) != 0;
    }
    if (malformed_request.size() >= 4)
    {
        const uint8_t low_flags = std::to_integer<uint8_t>(malformed_request[3]);
        response_header.checking_disabled = (low_flags & 0x10U) != 0;
    }

    return write_question_message(response_header, {}, maximum_size);
}

} // namespace dns::protocol
