#pragma once

#include "protocol/DomainName.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace dns::protocol
{

inline constexpr size_t kDnsHeaderSize = 12;

enum class RecordType : uint16_t
{
    A     = 1,
    NS    = 2,
    CNAME = 5,
    SOA   = 6,
    PTR   = 12,
    HINFO = 13,
    MINFO = 14,
    MX    = 15,
    TXT   = 16,
    AAAA  = 28,
    OPT   = 41,
};

enum class RecordClass : uint16_t
{
    IN   = 1,
    NONE = 254,
    ANY  = 255,
};

enum class Opcode : uint8_t
{
    Query  = 0,
    IQuery = 1,
    Status = 2,
};

enum class ResponseCode : uint8_t
{
    NoError  = 0,
    FormErr  = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp   = 4,
    Refused  = 5,
};

struct Header
{
    uint16_t id{0};
    bool     is_response{false};
    uint8_t  opcode{static_cast<uint8_t>(Opcode::Query)};
    bool     authoritative_answer{false};
    bool     truncated{false};
    bool     recursion_desired{false};
    bool     recursion_available{false};
    bool     reserved_z{false};
    bool     authenticated_data{false};
    bool     checking_disabled{false};
    uint8_t  response_code{static_cast<uint8_t>(ResponseCode::NoError)};

    bool operator==(const Header &) const = default;
};

struct Question
{
    DomainName name;
    uint16_t   type{0};
    uint16_t   question_class{0};

    bool operator==(const Question &) const = default;
};

struct ResourceRecord
{
    DomainName             name;
    uint16_t               type{0};
    uint16_t               record_class{0};
    uint32_t               ttl{0};
    size_t                 rdata_offset{0};
    std::vector<std::byte> rdata;

    // RDATA is retained as opaque wire bytes. wire_image and rdata_offset keep
    // the original compression-pointer context available for later type-aware
    // decoding. Raw RDATA must not be copied into a newly laid-out message.
};

struct Message
{
    Header                      header;
    std::vector<Question>       questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additionals;
    std::vector<std::byte>      wire_image;
};

} // namespace dns::protocol
