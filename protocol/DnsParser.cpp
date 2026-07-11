#include "protocol/DnsParser.h"

#include "protocol/Wire.h"

#include <algorithm>
#include <cstdint>
#include <utility>

namespace dns::protocol
{
namespace
{

struct DecodedName
{
    DomainName name;
    size_t     next_offset{0};
};

std::unexpected<ParseError> parse_failure(ParseErrorCode code, size_t offset)
{
    return std::unexpected(ParseError{code, offset});
}

std::expected<DecodedName, ParseError> decode_name(std::span<const std::byte> packet,
                                                   size_t                     start,
                                                   size_t                     encoded_end,
                                                   const ParseLimits         &limits)
{
    std::vector<std::string> labels;
    std::vector<size_t>      visited_pointers;
    size_t                   position = start;
    size_t                   next_offset = start;
    size_t                   expanded_wire_size = 1;
    bool                     followed_pointer = false;

    while (true)
    {
        if (position >= packet.size())
            return parse_failure(ParseErrorCode::UnexpectedEnd, position);
        if (!followed_pointer && position >= encoded_end)
            return parse_failure(ParseErrorCode::UnexpectedEnd, position);

        const uint8_t length = std::to_integer<uint8_t>(packet[position]);

        if (length == 0)
        {
            if (!followed_pointer)
                next_offset = position + 1;
            break;
        }

        if ((length & 0xc0U) == 0xc0U)
        {
            if (position + 1 >= packet.size() || (!followed_pointer && position + 1 >= encoded_end))
                return parse_failure(ParseErrorCode::TruncatedCompressionPointer, position);

            const size_t pointer = (static_cast<size_t>(length & 0x3fU) << 8U) |
                                   static_cast<size_t>(std::to_integer<uint8_t>(packet[position + 1]));
            if (pointer >= packet.size())
                return parse_failure(ParseErrorCode::CompressionPointerOutOfBounds, position);
            if (limits.require_backward_pointers && pointer >= position)
                return parse_failure(ParseErrorCode::ForwardCompressionPointer, position);
            if (std::find(visited_pointers.begin(), visited_pointers.end(), pointer) != visited_pointers.end())
                return parse_failure(ParseErrorCode::CompressionPointerLoop, position);
            if (visited_pointers.size() >= limits.maximum_compression_pointers)
                return parse_failure(ParseErrorCode::TooManyCompressionPointers, position);

            visited_pointers.push_back(pointer);
            if (!followed_pointer)
                next_offset = position + 2;
            followed_pointer = true;
            position = pointer;
            continue;
        }

        if ((length & 0xc0U) != 0)
            return parse_failure(ParseErrorCode::InvalidLabelType, position);
        if (length > kMaxLabelSize)
            return parse_failure(ParseErrorCode::LabelTooLong, position);

        const size_t label_begin = position + 1;
        if (label_begin > packet.size() || static_cast<size_t>(length) > packet.size() - label_begin ||
            (!followed_pointer && (label_begin > encoded_end || static_cast<size_t>(length) > encoded_end - label_begin)))
            return parse_failure(ParseErrorCode::UnexpectedEnd, position);
        if (expanded_wire_size > kMaxDomainWireSize - (static_cast<size_t>(length) + 1))
            return parse_failure(ParseErrorCode::NameTooLong, position);

        labels.emplace_back(reinterpret_cast<const char *>(packet.data() + label_begin), length);
        expanded_wire_size += static_cast<size_t>(length) + 1;
        position = label_begin + length;
        if (!followed_pointer)
            next_offset = position;
    }

    auto name = DomainName::from_labels(std::move(labels));
    if (!name)
    {
        switch (name.error().code)
        {
            case DomainNameErrorCode::EmptyLabel:
                return parse_failure(ParseErrorCode::EmptyLabel, start);
            case DomainNameErrorCode::InvalidEscape:
                // Wire labels are already separated and never interpreted as
                // presentation-format escapes.
                return parse_failure(ParseErrorCode::InvalidLabelType, start);
            case DomainNameErrorCode::LabelTooLong:
                return parse_failure(ParseErrorCode::LabelTooLong, start);
            case DomainNameErrorCode::NameTooLong:
                return parse_failure(ParseErrorCode::NameTooLong, start);
        }
    }

    return DecodedName{std::move(*name), next_offset};
}

std::expected<Question, ParseError> parse_question(std::span<const std::byte> packet, size_t &offset, const ParseLimits &limits)
{
    auto decoded_name = decode_name(packet, offset, packet.size(), limits);
    if (!decoded_name)
        return std::unexpected(decoded_name.error());

    detail::WireReader reader{packet, decoded_name->next_offset};
    Question           question;
    question.name = std::move(decoded_name->name);
    if (!reader.read_u16(question.type) || !reader.read_u16(question.question_class))
        return parse_failure(ParseErrorCode::UnexpectedEnd, reader.offset());

    offset = reader.offset();
    return question;
}

std::expected<ResourceRecord, ParseError> parse_resource_record(std::span<const std::byte> packet, size_t &offset, const ParseLimits &limits)
{
    auto decoded_name = decode_name(packet, offset, packet.size(), limits);
    if (!decoded_name)
        return std::unexpected(decoded_name.error());

    detail::WireReader reader{packet, decoded_name->next_offset};
    ResourceRecord     record;
    uint16_t           rdata_length{0};
    record.name = std::move(decoded_name->name);

    if (!reader.read_u16(record.type) || !reader.read_u16(record.record_class) || !reader.read_u32(record.ttl) || !reader.read_u16(rdata_length))
        return parse_failure(ParseErrorCode::UnexpectedEnd, reader.offset());
    record.rdata_offset = reader.offset();
    if (!reader.read_bytes(rdata_length, record.rdata))
        return parse_failure(ParseErrorCode::UnexpectedEnd, reader.offset());

    const size_t rdata_end = reader.offset();
    const auto   validate_single_name = [&](size_t name_offset, size_t required_end) -> std::expected<void, ParseError> {
        auto decoded = decode_name(packet, name_offset, required_end, limits);
        if (!decoded)
            return std::unexpected(decoded.error());
        if (decoded->next_offset != required_end)
            return parse_failure(ParseErrorCode::InvalidRdata, decoded->next_offset);
        return {};
    };
    const auto validate_character_strings = [&](size_t expected_count) -> bool {
        size_t cursor = record.rdata_offset;
        size_t count  = 0;
        while (cursor < rdata_end)
        {
            const size_t string_size = std::to_integer<uint8_t>(packet[cursor++]);
            if (string_size > rdata_end - cursor)
                return false;
            cursor += string_size;
            ++count;
        }
        return cursor == rdata_end && count == expected_count;
    };
    const auto validate_text_strings = [&]() -> bool {
        size_t cursor = record.rdata_offset;
        size_t count  = 0;
        while (cursor < rdata_end)
        {
            const size_t string_size = std::to_integer<uint8_t>(packet[cursor++]);
            if (string_size > rdata_end - cursor)
                return false;
            cursor += string_size;
            ++count;
        }
        return cursor == rdata_end && count != 0;
    };

    switch (static_cast<RecordType>(record.type))
    {
        case RecordType::A:
            if (rdata_length != 4)
                return parse_failure(ParseErrorCode::InvalidRdata, record.rdata_offset);
            break;
        case RecordType::AAAA:
            if (rdata_length != 16)
                return parse_failure(ParseErrorCode::InvalidRdata, record.rdata_offset);
            break;
        case RecordType::NS:
        case RecordType::CNAME:
        case RecordType::PTR:
        {
            auto result = validate_single_name(record.rdata_offset, rdata_end);
            if (!result)
                return std::unexpected(result.error());
            break;
        }
        case RecordType::MX:
        {
            if (rdata_length < 3)
                return parse_failure(ParseErrorCode::InvalidRdata, record.rdata_offset);
            auto result = validate_single_name(record.rdata_offset + 2, rdata_end);
            if (!result)
                return std::unexpected(result.error());
            break;
        }
        case RecordType::SOA:
        {
            auto primary_name = decode_name(packet, record.rdata_offset, rdata_end, limits);
            if (!primary_name)
                return std::unexpected(primary_name.error());
            auto mailbox_name = decode_name(packet, primary_name->next_offset, rdata_end, limits);
            if (!mailbox_name)
                return std::unexpected(mailbox_name.error());
            if (mailbox_name->next_offset > rdata_end || rdata_end - mailbox_name->next_offset != 20)
                return parse_failure(ParseErrorCode::InvalidRdata, mailbox_name->next_offset);
            break;
        }
        case RecordType::MINFO:
        {
            auto responsible_mailbox = decode_name(packet, record.rdata_offset, rdata_end, limits);
            if (!responsible_mailbox)
                return std::unexpected(responsible_mailbox.error());
            auto result = validate_single_name(responsible_mailbox->next_offset, rdata_end);
            if (!result)
                return std::unexpected(result.error());
            break;
        }
        case RecordType::HINFO:
            if (!validate_character_strings(2))
                return parse_failure(ParseErrorCode::InvalidRdata, record.rdata_offset);
            break;
        case RecordType::TXT:
            if (!validate_text_strings())
                return parse_failure(ParseErrorCode::InvalidRdata, record.rdata_offset);
            break;
        case RecordType::OPT:
            // OPT option tuples are intentionally left opaque until EDNS is
            // enabled. Envelope bounds are still checked.
            break;
    }

    offset = reader.offset();
    return record;
}

template <typename Item, typename Parser>
std::expected<void, ParseError> parse_section(std::vector<Item> &output, uint16_t count, Parser &&parser)
{
    output.reserve(count);
    for (uint16_t index = 0; index < count; ++index)
    {
        auto item = parser();
        if (!item)
            return std::unexpected(item.error());
        output.push_back(std::move(*item));
    }
    return {};
}

} // namespace

ParseResult parse_message(std::span<const std::byte> packet, const ParseLimits &limits)
{
    if (packet.size() > limits.maximum_packet_size)
        return parse_failure(ParseErrorCode::PacketTooLarge, limits.maximum_packet_size);

    detail::WireReader reader{packet};
    Message            message;
    uint16_t           flags{0};
    uint16_t           question_count{0};
    uint16_t           answer_count{0};
    uint16_t           authority_count{0};
    uint16_t           additional_count{0};

    if (!reader.read_u16(message.header.id) || !reader.read_u16(flags) || !reader.read_u16(question_count) || !reader.read_u16(answer_count) ||
        !reader.read_u16(authority_count) || !reader.read_u16(additional_count))
        return parse_failure(ParseErrorCode::UnexpectedEnd, reader.offset());

    if (question_count > limits.maximum_questions)
        return parse_failure(ParseErrorCode::TooManyQuestions, 4);
    if (answer_count > limits.maximum_records_per_section || authority_count > limits.maximum_records_per_section ||
        additional_count > limits.maximum_records_per_section)
        return parse_failure(ParseErrorCode::TooManyRecords, 6);

    const size_t total_records = static_cast<size_t>(answer_count) + static_cast<size_t>(authority_count) + static_cast<size_t>(additional_count);
    if (total_records > limits.maximum_total_records)
        return parse_failure(ParseErrorCode::TooManyRecords, 6);

    message.header.is_response          = (flags & 0x8000U) != 0;
    message.header.opcode               = static_cast<uint8_t>((flags >> 11U) & 0x0fU);
    message.header.authoritative_answer = (flags & 0x0400U) != 0;
    message.header.truncated            = (flags & 0x0200U) != 0;
    message.header.recursion_desired    = (flags & 0x0100U) != 0;
    message.header.recursion_available  = (flags & 0x0080U) != 0;
    message.header.reserved_z           = (flags & 0x0040U) != 0;
    message.header.authenticated_data   = (flags & 0x0020U) != 0;
    message.header.checking_disabled    = (flags & 0x0010U) != 0;
    message.header.response_code        = static_cast<uint8_t>(flags & 0x000fU);

    size_t offset = reader.offset();

    auto questions_result = parse_section(message.questions, question_count, [&]() { return parse_question(packet, offset, limits); });
    if (!questions_result)
        return std::unexpected(questions_result.error());

    auto parse_rr = [&]() { return parse_resource_record(packet, offset, limits); };
    auto answers_result = parse_section(message.answers, answer_count, parse_rr);
    if (!answers_result)
        return std::unexpected(answers_result.error());
    auto authorities_result = parse_section(message.authorities, authority_count, parse_rr);
    if (!authorities_result)
        return std::unexpected(authorities_result.error());
    auto additionals_result = parse_section(message.additionals, additional_count, parse_rr);
    if (!additionals_result)
        return std::unexpected(additionals_result.error());

    if (limits.reject_trailing_data && offset != packet.size())
        return parse_failure(ParseErrorCode::TrailingData, offset);

    message.wire_image.assign(packet.begin(), packet.end());
    return message;
}

} // namespace dns::protocol
