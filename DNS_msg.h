#pragma once

// Transitional include for code that still includes DNS_msg.h. New code should
// include headers from protocol/ directly. The old bit-field wire structures
// were intentionally removed because their layout and byte order were not
// suitable for parsing network data.

#include "protocol/DnsMessage.h"

#include <cstddef>

inline constexpr size_t UDP_MAX = 512;

using DNS_Header   = dns::protocol::Header;
using DNS_Question = dns::protocol::Question;
using DNS_RR       = dns::protocol::ResourceRecord;
using DNS_Msg      = dns::protocol::Message;

inline constexpr int HEADER_QR_QUERY = 0;
inline constexpr int HEADER_QR_ANSER = 1;

inline constexpr int HEADER_OPCODE_QUERY  = static_cast<int>(dns::protocol::Opcode::Query);
inline constexpr int HEADER_OPCODE_IQUERY = static_cast<int>(dns::protocol::Opcode::IQuery);
inline constexpr int HEADER_OPCODE_STATUS = static_cast<int>(dns::protocol::Opcode::Status);

inline constexpr int HEADER_RCODE_NO_ERROR   = static_cast<int>(dns::protocol::ResponseCode::NoError);
inline constexpr int HEADER_RCODE_NAME_ERROR = static_cast<int>(dns::protocol::ResponseCode::NxDomain);

inline constexpr int TYPE_A     = static_cast<int>(dns::protocol::RecordType::A);
inline constexpr int TYPE_NS    = static_cast<int>(dns::protocol::RecordType::NS);
inline constexpr int TYPE_CNAME = static_cast<int>(dns::protocol::RecordType::CNAME);
inline constexpr int TYPE_SOA   = static_cast<int>(dns::protocol::RecordType::SOA);
inline constexpr int TYPE_PTR   = static_cast<int>(dns::protocol::RecordType::PTR);
inline constexpr int TYPE_HINFO = static_cast<int>(dns::protocol::RecordType::HINFO);
inline constexpr int TYPE_MINFO = static_cast<int>(dns::protocol::RecordType::MINFO);
inline constexpr int TYPE_MX    = static_cast<int>(dns::protocol::RecordType::MX);
inline constexpr int TYPE_TXT   = static_cast<int>(dns::protocol::RecordType::TXT);
inline constexpr int TYPE_AAAA  = static_cast<int>(dns::protocol::RecordType::AAAA);

inline constexpr int CLASS_IN  = static_cast<int>(dns::protocol::RecordClass::IN);
inline constexpr int CLASS_NOT = static_cast<int>(dns::protocol::RecordClass::NONE);
inline constexpr int CLASS_ALL = static_cast<int>(dns::protocol::RecordClass::ANY);
