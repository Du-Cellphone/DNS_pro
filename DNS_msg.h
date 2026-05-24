#pragma once
#include <memory>
#include <string>
#include <cstddef>

constexpr size_t UDP_MAX = 512;

constexpr int HEADER_QR_QUERY = 0;
constexpr int HEADER_QR_ANSER = 1;

constexpr int HEADER_OPCODE_QUERY  = 0;
constexpr int HEADER_OPCODE_IQUERY = 1;
constexpr int HEADER_OPCODE_STATUS = 2;

constexpr int HEADER_RCODE_NO_ERROR   = 0;
constexpr int HEADER_RCODE_NAME_ERROR = 3;

constexpr int TYPE_A     = 1;
constexpr int TYPE_NS    = 2;
constexpr int TYPE_CNAME = 5;
constexpr int TYPE_SOA   = 6;
constexpr int TYPE_PTR   = 12;
constexpr int TYPE_HINFO = 13;
constexpr int TYPE_MINFO = 14;
constexpr int TYPE_MX    = 15;
constexpr int TYPE_TXT   = 16;
constexpr int TYPE_AAAA  = 28;

constexpr int CLASS_IN  = 1;
constexpr int CLASS_NOT = 254;
constexpr int CLASS_ALL = 255;

struct DNS_Header
{
    unsigned short id;

    std::byte qr : 1;
    std::byte opcode : 4;
    std::byte aa : 1;
    std::byte tc : 1;
    std::byte rd : 1;
    std::byte ra : 1;
    std::byte z : 3;
    std::byte rcode : 4;

    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

struct DNS_Question
{
    std::string    qname;
    unsigned short qtype;
    unsigned short qclass;

    std::unique_ptr<DNS_Question> next;
};

struct DNS_RR
{
    std::string    name;
    unsigned short type;
    unsigned short _class;
    unsigned int   ttl;
    unsigned short rdlength;
    std::string    rdata;

    std::unique_ptr<DNS_RR> next;
};

struct DNS_Msg
{
    std::unique_ptr<DNS_Header>   header;
    std::unique_ptr<DNS_Question> question;
    std::unique_ptr<DNS_RR>       RRs;
};