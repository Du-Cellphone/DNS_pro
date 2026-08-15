#pragma once

#include "common/Expected.h"
#include "protocol/DnsMessage.h"

namespace dns::protocol
{

enum class QueryErrorCode
{
    NotAQuery,
    UnsupportedOpcode,
    InvalidHeaderFlags,
    WrongQuestionCount,
    UnexpectedAnswerSection,
    ExtensionsNotSupported,
    UnsupportedType,
    UnsupportedClass,
};

struct QueryError
{
    QueryErrorCode code;

    bool operator==(const QueryError &) const = default;
};

using QueryValidationResult = std::expected<Question, QueryError>;

QueryValidationResult validate_mvp_query(const Message &message);
ResponseCode          response_code_for(QueryErrorCode error) noexcept;

} // namespace dns::protocol
