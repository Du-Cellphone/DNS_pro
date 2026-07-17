#include "protocol/DnsParser.h"
#include "protocol/DnsQuery.h"
#include "protocol/DnsResponse.h"
#include "protocol/DnsWriter.h"
#include "protocol/DomainName.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace dns::protocol;

[[noreturn]] void fail(std::string_view message)
{
    std::cerr << "protocol test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

void require(bool condition, std::string_view message)
{
    if (!condition)
        fail(message);
}

std::vector<std::byte> bytes(std::initializer_list<uint8_t> values)
{
    std::vector<std::byte> result;
    result.reserve(values.size());
    for (uint8_t value : values)
        result.push_back(static_cast<std::byte>(value));
    return result;
}

const std::vector<std::byte> &mixed_case_a_query()
{
    static const auto packet = bytes({
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'W',  'W',  'W',  0x07, 'E',  'x',  'A',  'm',  'p',  'l',  'e',
        0x03, 'C',  'O',  'M',  0x00, 0x00, 0x01, 0x00, 0x01,
    });
    return packet;
}

const std::vector<std::byte> &compressed_a_response()
{
    static const auto packet = bytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04,
    });
    return packet;
}

void test_header_and_big_endian_fields()
{
    auto packet = bytes({
        0x12, 0x34, 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    });
    auto parsed = parse_message(packet);
    require(parsed.has_value(), "a complete header must parse");

    const Header &header = parsed->header;
    require(header.id == 0x1234, "transaction ID must use network byte order");
    require(header.is_response, "QR bit must be decoded");
    require(header.opcode == 5, "opcode bits must be decoded");
    require(!header.authoritative_answer, "AA bit must be decoded");
    require(header.truncated, "TC bit must be decoded");
    require(header.recursion_desired, "RD bit must be decoded");
    require(header.recursion_available, "RA bit must be decoded");
    require(header.reserved_z, "reserved Z bit must be decoded separately");
    require(!header.authenticated_data, "AD bit must be decoded separately");
    require(!header.checking_disabled, "CD bit must be decoded separately");
    require(header.response_code == 13, "RCODE bits must be decoded");

    for (size_t length = 0; length < kDnsHeaderSize; ++length)
    {
        const auto prefix = std::span<const std::byte>{packet}.first(length);
        auto       result = parse_message(prefix);
        require(!result && result.error().code == ParseErrorCode::UnexpectedEnd, "every truncated header must be rejected");
    }
}

void test_domain_name_model()
{
    auto name = DomainName::from_text("WWW.Example.COM.");
    require(name.has_value(), "a normal presentation name must be accepted");
    require(name->to_string() == "WWW.Example.COM", "original case must be retained");
    require(name->to_canonical_string() == "www.example.com", "canonical form must lowercase ASCII only");

    auto equivalent = DomainName::from_text("www.example.com");
    require(equivalent && *name == *equivalent, "DNS name equality must be ASCII case-insensitive");

    auto parent = DomainName::from_text("example.com");
    require(parent && name->is_subdomain_of(*parent), "a child name must recognize its parent domain");
    require(!parent->is_subdomain_of(*name), "a parent must not match a more specific child");

    auto one_label_with_dot = DomainName::from_labels({"a.b"});
    auto two_labels = DomainName::from_text("a.b");
    require(one_label_with_dot && two_labels && *one_label_with_dot != *two_labels, "label boundaries must be part of the canonical key");
    require(one_label_with_dot->to_string() == "a\\.b", "presentation output must escape a dot inside one label");
    require(DomainName::from_text(one_label_with_dot->to_string()) == one_label_with_dot,
            "escaped presentation output must round-trip without losing label boundaries");

    auto binary_label = DomainName::from_labels({std::string{"a\0b", 3}});
    require(binary_label && binary_label->to_string() == "a\\000b", "non-printable label bytes must use a three-digit escape");
    require(DomainName::from_text(binary_label->to_string()) == binary_label, "numeric presentation escapes must round-trip binary label bytes");

    require(DomainName::from_text("")->is_root(), "an empty presentation name represents the root");
    require(DomainName::from_text(".")->is_root(), "a single dot represents the root");
    require(!DomainName::from_text(".example.com"), "a leading empty label must be rejected");
    require(!DomainName::from_text("example..com"), "an interior empty label must be rejected");
    require(!DomainName::from_text("example.com.."), "multiple trailing dots must be rejected");
    auto invalid_escape = DomainName::from_text("example\\");
    require(!invalid_escape && invalid_escape.error().code == DomainNameErrorCode::InvalidEscape, "a dangling presentation escape must be rejected");
    require(!DomainName::from_text("\\999.example"), "a numeric escape outside one byte must be rejected");

    const std::string label63(63, 'a');
    const std::string label64(64, 'a');
    require(DomainName::from_text(label63).has_value(), "a 63-byte label must be accepted");
    auto too_long_label = DomainName::from_text(label64);
    require(!too_long_label && too_long_label.error().code == DomainNameErrorCode::LabelTooLong, "a 64-byte label must be rejected");

    auto maximum_name = DomainName::from_labels({std::string(63, 'a'), std::string(63, 'b'), std::string(63, 'c'), std::string(61, 'd')});
    require(maximum_name && maximum_name->wire_size() == 255, "an expanded 255-byte name must be accepted");
    auto oversized_name = DomainName::from_labels({std::string(63, 'a'), std::string(63, 'b'), std::string(63, 'c'), std::string(62, 'd')});
    require(!oversized_name && oversized_name.error().code == DomainNameErrorCode::NameTooLong, "an expanded 256-byte name must be rejected");

    Header maximum_header;
    Question maximum_question{*maximum_name, static_cast<uint16_t>(RecordType::A), static_cast<uint16_t>(RecordClass::IN)};
    const std::array maximum_questions{maximum_question};
    auto maximum_wire = serialize_query(maximum_header, maximum_questions);
    require(maximum_wire && parse_message(*maximum_wire).has_value(), "a 255-byte expanded name must survive wire round-trip");

    auto oversized_wire = bytes({
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    });
    for (const auto &[length, value] : std::array<std::pair<uint8_t, uint8_t>, 4>{
             std::pair<uint8_t, uint8_t>{63, 'a'}, {63, 'b'}, {63, 'c'}, {62, 'd'}})
    {
        oversized_wire.push_back(static_cast<std::byte>(length));
        oversized_wire.insert(oversized_wire.end(), length, static_cast<std::byte>(value));
    }
    const auto question_tail = bytes({0x00, 0x00, 0x01, 0x00, 0x01});
    oversized_wire.insert(oversized_wire.end(), question_tail.begin(), question_tail.end());
    auto oversized_wire_result = parse_message(oversized_wire);
    require(!oversized_wire_result && oversized_wire_result.error().code == ParseErrorCode::NameTooLong,
            "a wire name that expands beyond 255 bytes must be rejected");
}

void test_query_parse_write_roundtrip()
{
    const auto &packet = mixed_case_a_query();
    auto        parsed = parse_message(packet);
    require(parsed.has_value(), "a normal A query must parse");
    require(parsed->questions.size() == 1, "question count must be decoded");

    const Question &question = parsed->questions.front();
    require(question.name.to_string() == "WWW.ExAmple.COM", "wire label spelling and case must be retained");
    require(question.name.to_canonical_string() == "www.example.com", "wire name must expose a canonical form");
    require(question.type == static_cast<uint16_t>(RecordType::A), "QTYPE must use network byte order");
    require(question.question_class == static_cast<uint16_t>(RecordClass::IN), "QCLASS must use network byte order");

    auto validated = validate_mvp_query(*parsed);
    require(validated.has_value(), "a single IN/A query must satisfy MVP policy");

    auto serialized = serialize_query(parsed->header, parsed->questions);
    require(serialized && *serialized == packet, "an uncompressed query must round-trip without losing question case");

    Message aaaa = *parsed;
    aaaa.questions.front().type = static_cast<uint16_t>(RecordType::AAAA);
    require(validate_mvp_query(aaaa).has_value(), "an IN/AAAA query must satisfy MVP policy");

    Header root_header;
    root_header.id = 7;
    Question root_question{DomainName{}, static_cast<uint16_t>(RecordType::A), static_cast<uint16_t>(RecordClass::IN)};
    const std::array root_questions{root_question};
    auto root_wire = serialize_query(root_header, root_questions);
    require(root_wire.has_value(), "a root-domain query must serialize");
    auto root_parsed = parse_message(*root_wire);
    require(root_parsed && root_parsed->questions.front().name.is_root(), "a root-domain query must round-trip");
}


void test_transaction_id_rewrite()
{
    const auto original = compressed_a_response();
    auto       rewritten = original;

    auto result = rewrite_transaction_id(rewritten, 0xbeef);
    require(result.has_value(), "a complete DNS packet must allow its transaction ID to be rewritten");
    require(transaction_id(rewritten) == std::optional<uint16_t>{0xbeef}, "the rewritten transaction ID must use network byte order");
    require(rewritten[0] == std::byte{0xbe} && rewritten[1] == std::byte{0xef}, "transaction ID bytes must be written most significant byte first");

    rewritten[0] = original[0];
    rewritten[1] = original[1];
    require(rewritten == original, "rewriting a transaction ID must not alter any other wire byte");

    auto one_byte = bytes({0x12});
    const auto unchanged = one_byte;
    auto missing_id = rewrite_transaction_id(one_byte, 0x3456);
    require(!missing_id && missing_id.error().code == WriteErrorCode::MissingTransactionId,
            "a packet shorter than two bytes must reject transaction ID rewriting");
    require(one_byte == unchanged, "a failed transaction ID rewrite must not partially modify its input");
    require(!transaction_id(one_byte), "reading a transaction ID must reject a packet shorter than two bytes");
}

void test_upstream_response_validation()
{
    auto response = parse_message(compressed_a_response());
    require(response.has_value(), "upstream response validation fixture must parse");
    const Question expected_question = response->questions.front();

    auto valid = validate_upstream_response(*response, 0x1234, static_cast<uint8_t>(Opcode::Query), expected_question);
    require(valid.has_value(), "a correlated upstream response must pass validation");

    Message different_case = *response;
    auto uppercase_name = DomainName::from_text("EXAMPLE.COM");
    require(uppercase_name.has_value(), "case-insensitive response validation fixture must be valid");
    different_case.questions.front().name = std::move(*uppercase_name);
    require(validate_upstream_response(different_case, 0x1234, static_cast<uint8_t>(Opcode::Query), expected_question).has_value(),
            "question association must use DNS case-insensitive name equality");

    Message legal_response_flags = *response;
    legal_response_flags.header.authoritative_answer = true;
    legal_response_flags.header.truncated = true;
    legal_response_flags.header.authenticated_data = true;
    legal_response_flags.header.checking_disabled = true;
    legal_response_flags.header.response_code = static_cast<uint8_t>(ResponseCode::NxDomain);
    require(validate_upstream_response(legal_response_flags, 0x1234, static_cast<uint8_t>(Opcode::Query), expected_question).has_value(),
            "association validation must not reject legal response-only flags or non-success RCODEs");

    Message not_a_response = *response;
    not_a_response.header.is_response = false;
    auto not_response = validate_upstream_response(not_a_response, 0x1234, static_cast<uint8_t>(Opcode::Query), expected_question);
    require(!not_response && not_response.error().code == ResponseValidationErrorCode::NotAResponse,
            "a query packet must not complete an upstream response wait");

    auto wrong_id = validate_upstream_response(*response, 0x4321, static_cast<uint8_t>(Opcode::Query), expected_question);
    require(!wrong_id && wrong_id.error().code == ResponseValidationErrorCode::WrongTransactionId,
            "an upstream response with another transaction ID must be rejected");

    auto wrong_opcode = validate_upstream_response(*response, 0x1234, static_cast<uint8_t>(Opcode::Status), expected_question);
    require(!wrong_opcode && wrong_opcode.error().code == ResponseValidationErrorCode::WrongOpcode,
            "an upstream response with another opcode must be rejected");

    Message reserved_flag = *response;
    reserved_flag.header.reserved_z = true;
    auto invalid_flags = validate_upstream_response(reserved_flag, 0x1234, static_cast<uint8_t>(Opcode::Query), expected_question);
    require(!invalid_flags && invalid_flags.error().code == ResponseValidationErrorCode::InvalidHeaderFlags,
            "an upstream response with the reserved header bit set must be rejected");

    Message no_question = *response;
    no_question.questions.clear();
    auto wrong_count = validate_upstream_response(no_question, 0x1234, static_cast<uint8_t>(Opcode::Query), expected_question);
    require(!wrong_count && wrong_count.error().code == ResponseValidationErrorCode::WrongQuestionCount,
            "an upstream response must echo exactly one question");

    Question mismatched_question = expected_question;
    mismatched_question.type = static_cast<uint16_t>(RecordType::AAAA);
    auto mismatch = validate_upstream_response(*response, 0x1234, static_cast<uint8_t>(Opcode::Query), mismatched_question);
    require(!mismatch && mismatch.error().code == ResponseValidationErrorCode::QuestionMismatch,
            "an upstream response must match the pending question tuple");
}

void test_compression_and_resource_records()
{
    auto parsed = parse_message(compressed_a_response());
    require(parsed.has_value(), "a response with a backward owner-name pointer must parse");
    require(parsed->wire_image == compressed_a_response(), "an owning parse result must retain the original pointer context");
    require(parsed->answers.size() == 1, "answer count must be decoded");

    const ResourceRecord &answer = parsed->answers.front();
    require(answer.name.to_canonical_string() == "example.com", "compressed owner name must be expanded");
    require(answer.type == static_cast<uint16_t>(RecordType::A), "RR TYPE must be decoded");
    require(answer.record_class == static_cast<uint16_t>(RecordClass::IN), "RR CLASS must be decoded");
    require(answer.ttl == 60, "RR TTL must use network byte order");
    require(answer.rdata_offset + answer.rdata.size() == compressed_a_response().size(), "RDATA must retain its absolute wire offset");
    require(answer.rdata == bytes({1, 2, 3, 4}), "opaque RDATA bytes must be retained");

    const auto two_questions = bytes({
        0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
        0x03, 'w',  'w',  'w',  0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01,
    });
    auto parsed_questions = parse_message(two_questions);
    require(parsed_questions && parsed_questions->questions.size() == 2, "a pointer after an inline prefix must advance to QTYPE correctly");
    require(parsed_questions->questions[1].name.to_canonical_string() == "www.example.com", "a compressed suffix must be expanded");
    require(parsed_questions->questions[1].type == static_cast<uint16_t>(RecordType::AAAA), "fields after a pointer must be read at the encoded endpoint");

    auto valid_cname = bytes({
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x05, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x0c,
    });
    require(parse_message(valid_cname).has_value(), "a domain-name RDATA pointer must be validated in the original packet context");

    auto invalid_cname = valid_cname;
    invalid_cname.back() = std::byte{0xff};
    auto invalid_cname_result = parse_message(invalid_cname);
    require(!invalid_cname_result && invalid_cname_result.error().code == ParseErrorCode::CompressionPointerOutOfBounds,
            "an invalid compression pointer inside known name RDATA must be rejected");

    auto invalid_a = compressed_a_response();
    invalid_a[invalid_a.size() - 5] = std::byte{0x03};
    invalid_a.pop_back();
    auto invalid_a_result = parse_message(invalid_a);
    require(!invalid_a_result && invalid_a_result.error().code == ParseErrorCode::InvalidRdata,
            "A RDATA must contain exactly four bytes");

    auto unknown_record = valid_cname;
    unknown_record[31] = std::byte{0xfd};
    unknown_record[32] = std::byte{0xe8}; // TYPE 65000
    unknown_record.back() = std::byte{0xff};
    require(parse_message(unknown_record).has_value(), "unknown RDATA must remain safely opaque instead of being misinterpreted");
}

void test_compression_failures()
{
    auto pointer_into_header = bytes({
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x01, 0x00, 0x01,
    });
    auto header_pointer_result = parse_message(pointer_into_header);
    require(!header_pointer_result && header_pointer_result.error().code == ParseErrorCode::CompressionPointerIntoHeader,
            "a compression pointer into the DNS header must be rejected before transaction ID rewriting can change name semantics");

    auto self_loop = bytes({
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    });
    auto strict_result = parse_message(self_loop);
    require(!strict_result && strict_result.error().code == ParseErrorCode::ForwardCompressionPointer,
            "strict parsing must reject a non-backward compression pointer");

    ParseLimits permissive;
    permissive.require_backward_pointers = false;
    auto loop_result = parse_message(self_loop, permissive);
    require(!loop_result && loop_result.error().code == ParseErrorCode::CompressionPointerLoop, "a self pointer must not loop forever");

    auto two_node_loop = bytes({
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x0e, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    });
    auto two_node_result = parse_message(two_node_loop, permissive);
    require(!two_node_result && two_node_result.error().code == ParseErrorCode::CompressionPointerLoop, "a multi-pointer cycle must be detected");

    ParseLimits no_jumps = permissive;
    no_jumps.maximum_compression_pointers = 0;
    auto jump_limit_result = parse_message(self_loop, no_jumps);
    require(!jump_limit_result && jump_limit_result.error().code == ParseErrorCode::TooManyCompressionPointers,
            "the pointer jump limit must be enforced before following a pointer");

    auto out_of_bounds = self_loop;
    out_of_bounds[13] = std::byte{0xff};
    auto bounds_result = parse_message(out_of_bounds, permissive);
    require(!bounds_result && bounds_result.error().code == ParseErrorCode::CompressionPointerOutOfBounds,
            "an out-of-packet pointer must be rejected");

    auto truncated_pointer = bytes({
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
    });
    auto truncated_result = parse_message(truncated_pointer);
    require(!truncated_result && truncated_result.error().code == ParseErrorCode::TruncatedCompressionPointer,
            "a one-byte compression pointer must be rejected");

    for (uint8_t reserved_prefix : {uint8_t{0x40}, uint8_t{0x80}})
    {
        auto invalid_label = bytes({
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, reserved_prefix,
        });
        auto invalid_result = parse_message(invalid_label);
        require(!invalid_result && invalid_result.error().code == ParseErrorCode::InvalidLabelType,
                "reserved label encodings must be rejected");
    }
}

void test_truncation_counts_and_limits()
{
    const auto &query = mixed_case_a_query();
    for (size_t length = 0; length < query.size(); ++length)
    {
        auto result = parse_message(std::span<const std::byte>{query}.first(length));
        require(!result, "every proper prefix of a complete query must fail parsing");
    }

    auto truncated_rdata = compressed_a_response();
    truncated_rdata.pop_back();
    auto rdata_result = parse_message(truncated_rdata);
    require(!rdata_result && rdata_result.error().code == ParseErrorCode::UnexpectedEnd, "RDLENGTH larger than available RDATA must be rejected");

    auto excessive_questions = bytes({
        0x00, 0x01, 0x01, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    });
    auto question_limit_result = parse_message(excessive_questions);
    require(!question_limit_result && question_limit_result.error().code == ParseErrorCode::TooManyQuestions,
            "question limits must be checked before allocation or item parsing");

    auto excessive_records = bytes({
        0x00, 0x01, 0x81, 0x80, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    });
    auto record_limit_result = parse_message(excessive_records);
    require(!record_limit_result && record_limit_result.error().code == ParseErrorCode::TooManyRecords,
            "record limits must be checked before allocation or item parsing");

    auto trailing = query;
    trailing.push_back(std::byte{0});
    auto trailing_result = parse_message(trailing);
    require(!trailing_result && trailing_result.error().code == ParseErrorCode::TrailingData, "unaccounted trailing bytes must be rejected by default");

    ParseLimits allow_trailing;
    allow_trailing.reject_trailing_data = false;
    require(parse_message(trailing, allow_trailing).has_value(), "callers may explicitly permit trailing bytes");

    ParseLimits tiny_packet;
    tiny_packet.maximum_packet_size = query.size() - 1;
    auto packet_limit_result = parse_message(query, tiny_packet);
    require(!packet_limit_result && packet_limit_result.error().code == ParseErrorCode::PacketTooLarge, "the configured packet-size limit must be enforced");
}

void test_mvp_policy_validation()
{
    auto parsed = parse_message(mixed_case_a_query());
    require(parsed.has_value(), "policy fixture must parse");

    Message candidate = *parsed;
    candidate.header.is_response = true;
    auto result = validate_mvp_query(candidate);
    require(!result && result.error().code == QueryErrorCode::NotAQuery, "responses must not enter query processing");

    candidate = *parsed;
    candidate.header.opcode = static_cast<uint8_t>(Opcode::Status);
    result = validate_mvp_query(candidate);
    require(!result && result.error().code == QueryErrorCode::UnsupportedOpcode, "non-QUERY opcodes must be reported as unsupported");
    require(response_code_for(result.error().code) == ResponseCode::NotImp, "unsupported opcodes must map to NOTIMP");

    candidate = *parsed;
    candidate.header.reserved_z = true;
    result = validate_mvp_query(candidate);
    require(!result && result.error().code == QueryErrorCode::InvalidHeaderFlags, "the reserved header bit must be rejected by MVP policy");
    require(response_code_for(result.error().code) == ResponseCode::FormErr, "invalid query flags must map to FORMERR");

    candidate = *parsed;
    candidate.questions.clear();
    result = validate_mvp_query(candidate);
    require(!result && result.error().code == QueryErrorCode::WrongQuestionCount, "MVP requires exactly one question");
    require(response_code_for(result.error().code) == ResponseCode::FormErr, "invalid question count must map to FORMERR");

    candidate = *parsed;
    candidate.questions.front().type = static_cast<uint16_t>(RecordType::MX);
    result = validate_mvp_query(candidate);
    require(!result && result.error().code == QueryErrorCode::UnsupportedType, "non-A/AAAA types must be reported as unsupported");

    candidate = *parsed;
    candidate.questions.front().question_class = static_cast<uint16_t>(RecordClass::ANY);
    result = validate_mvp_query(candidate);
    require(!result && result.error().code == QueryErrorCode::UnsupportedClass, "non-IN classes must be reported as unsupported");

    candidate = *parsed;
    candidate.additionals.emplace_back();
    result = validate_mvp_query(candidate);
    require(!result && result.error().code == QueryErrorCode::ExtensionsNotSupported, "additional records are outside the MVP policy");

    candidate = *parsed;
    candidate.answers.emplace_back();
    result = validate_mvp_query(candidate);
    require(!result && result.error().code == QueryErrorCode::UnexpectedAnswerSection, "queries with answer data must be rejected as malformed");
}

void test_error_response_writer()
{
    auto request = parse_message(mixed_case_a_query());
    require(request.has_value(), "response writer fixture must parse");

    auto refused_wire = make_error_response(*request, ResponseCode::Refused);
    require(refused_wire.has_value(), "a REFUSED response must serialize");
    auto refused = parse_message(*refused_wire);
    require(refused.has_value(), "a generated REFUSED response must parse");
    require(refused->header.id == request->header.id, "an error response must preserve the client transaction ID");
    require(refused->header.is_response, "an error response must set QR");
    require(refused->header.response_code == static_cast<uint8_t>(ResponseCode::Refused), "an error response must set RCODE");
    require(refused->header.recursion_desired == request->header.recursion_desired, "an error response must preserve RD");
    require(refused->header.recursion_available, "the forwarder must advertise recursion availability when configured");
    require(refused->questions == request->questions, "an error response must echo the original question and its case");
    require(refused->answers.empty() && refused->authorities.empty() && refused->additionals.empty(), "an error response must have zero RR counts");

    auto malformed = bytes({0xbe, 0xef, 0x29, 0x10}); // opcode 5, RD and CD set
    auto format_wire = make_format_error_response(malformed);
    require(format_wire.has_value(), "FORMERR can be generated when a transaction ID is available");
    auto format = parse_message(*format_wire);
    require(format.has_value(), "generated FORMERR must parse");
    require(format->header.id == 0xbeef, "FORMERR must preserve an available transaction ID");
    require(format->header.opcode == 5, "FORMERR must preserve an available opcode");
    require(format->header.recursion_desired && format->header.checking_disabled, "FORMERR must preserve available RD/CD bits");
    require(format->header.response_code == static_cast<uint8_t>(ResponseCode::FormErr), "malformed input must produce FORMERR");
    require(format->questions.empty(), "FORMERR from an unparsed request must not copy unvalidated bytes as a question");

    auto missing_id = make_format_error_response(bytes({0x12}));
    require(!missing_id && missing_id.error().code == WriteErrorCode::MissingTransactionId,
            "a response must not invent a transaction ID for an input shorter than two bytes");

    auto response_input = make_format_error_response(bytes({0x12, 0x34, 0x80, 0x00}));
    require(!response_input && response_input.error().code == WriteErrorCode::ExpectedQuery,
            "FORMERR generation must not answer another response and create a response loop");

    auto truncated_response_input = make_format_error_response(bytes({0x12, 0x34, 0x80}));
    require(!truncated_response_input && truncated_response_input.error().code == WriteErrorCode::ExpectedQuery,
            "a three-byte truncated response must still be recognized from the high QR bit");

    auto partial_flags = make_format_error_response(bytes({0x12, 0x34, 0x29}));
    require(partial_flags.has_value(), "a three-byte malformed query has enough flags to produce FORMERR");
    auto partial_flags_response = parse_message(*partial_flags);
    require(partial_flags_response && partial_flags_response->header.opcode == 5 && partial_flags_response->header.recursion_desired,
            "FORMERR must retain opcode and RD from an available high flags byte");

    auto too_small = make_error_response(*request, ResponseCode::ServFail, true, kDnsHeaderSize - 1);
    require(!too_small && too_small.error().code == WriteErrorCode::MessageTooLarge, "writer capacity failure must return an error without partial output");

    auto invalid_rcode = make_error_response(*request, static_cast<ResponseCode>(16));
    require(!invalid_rcode && invalid_rcode.error().code == WriteErrorCode::InvalidResponseCode, "an RCODE wider than four bits must be rejected");

    auto invalid_maximum = make_error_response(*request, ResponseCode::ServFail, true, 65'536);
    require(!invalid_maximum && invalid_maximum.error().code == WriteErrorCode::InvalidMaximumSize,
            "DNS messages cannot use a size limit wider than the 16-bit protocol maximum");
}

void test_address_response_writer()
{
    auto request = parse_message(mixed_case_a_query());
    require(request.has_value(), "address response fixture must parse");
    request->header.id                = 0xabcd;
    request->header.checking_disabled = true;

    const std::array first{std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1}};
    const std::array second{std::byte{192}, std::byte{0}, std::byte{2}, std::byte{2}};
    const std::array answers{AddressAnswerView{first}, AddressAnswerView{second}};
    auto             wire = make_address_response(*request, answers, 17);
    require(wire.has_value(), "a cached A RRset must serialize");

    auto response = parse_message(*wire);
    require(response && response->header.id == 0xabcd && response->header.is_response,
            "an address response must use the current client transaction ID and set QR");
    require(response->header.recursion_desired && response->header.recursion_available && response->header.checking_disabled,
            "an address response must preserve RD/CD and advertise recursion availability");
    require(response->questions == request->questions && response->questions.front().name.to_string() == "WWW.ExAmple.COM",
            "a cache hit must echo the current question spelling instead of an older cached query");
    require(response->answers.size() == 2 && response->answers[0].name == request->questions.front().name &&
                response->answers[1].name == request->questions.front().name,
            "every cached address must be emitted as one direct answer for the requested owner");
    require(response->answers[0].ttl == 17 && response->answers[1].ttl == 17 && response->answers[0].rdata == std::vector(first.begin(), first.end()) &&
                response->answers[1].rdata == std::vector(second.begin(), second.end()),
            "a cached RRset must preserve address order and use its remaining TTL");

    const std::array invalid{AddressAnswerView{std::span<const std::byte>{first}.first(3)}};
    auto             invalid_length = make_address_response(*request, invalid, 10);
    require(!invalid_length && invalid_length.error().code == WriteErrorCode::InvalidAddressLength,
            "an A cache response must reject non-four-byte RDATA");
    auto no_answers = make_address_response(*request, std::span<const AddressAnswerView>{}, 10);
    require(!no_answers && no_answers.error().code == WriteErrorCode::MissingAnswers, "an empty positive response must not serialize");

    Message unsupported = *request;
    unsupported.questions.front().type = static_cast<uint16_t>(RecordType::MX);
    auto unsupported_type = make_address_response(unsupported, answers, 10);
    require(!unsupported_type && unsupported_type.error().code == WriteErrorCode::UnsupportedAddressType,
            "the positive cache writer must remain limited to A and AAAA");

    Message aaaa_request = *request;
    aaaa_request.questions.front().type = static_cast<uint16_t>(RecordType::AAAA);
    std::array<std::byte, 16> ipv6{};
    ipv6[15] = std::byte{1};
    const std::array aaaa_answers{AddressAnswerView{ipv6}};
    auto             aaaa_wire = make_address_response(aaaa_request, aaaa_answers, 30);
    require(aaaa_wire.has_value(), "a cached AAAA RRset must serialize");
    auto aaaa = parse_message(*aaaa_wire);
    require(aaaa && aaaa->answers.size() == 1 && aaaa->answers.front().type == static_cast<uint16_t>(RecordType::AAAA) &&
                aaaa->answers.front().rdata.size() == 16,
            "a cached AAAA response must use sixteen-byte RDATA");

    auto too_small = make_address_response(*request, answers, 10, true, kDnsHeaderSize);
    require(!too_small && too_small.error().code == WriteErrorCode::MessageTooLarge,
            "address response capacity failure must not return a partial packet");
}

void test_deterministic_robustness_corpus()
{
    const std::array corpus{mixed_case_a_query(), compressed_a_response()};
    constexpr std::array<uint8_t, 6> replacements{0x00, 0x3f, 0x40, 0x80, 0xc0, 0xff};

    for (const auto &seed : corpus)
    {
        for (size_t index = 0; index < seed.size(); ++index)
        {
            for (uint8_t replacement : replacements)
            {
                auto mutated = seed;
                mutated[index] = static_cast<std::byte>(replacement);
                static_cast<void>(parse_message(mutated));
            }
        }
    }
}

} // namespace

int main()
{
    test_header_and_big_endian_fields();
    test_domain_name_model();
    test_query_parse_write_roundtrip();
    test_transaction_id_rewrite();
    test_upstream_response_validation();
    test_compression_and_resource_records();
    test_compression_failures();
    test_truncation_counts_and_limits();
    test_mvp_policy_validation();
    test_error_response_writer();
    test_address_response_writer();
    test_deterministic_robustness_corpus();

    std::cout << "all protocol tests passed\n";
    return EXIT_SUCCESS;
}
