#include "protocol/DnsQuery.h"

namespace dns::protocol
{

QueryValidationResult validate_mvp_query(const Message &message)
{
    if (message.header.is_response)
        return std::unexpected(QueryError{QueryErrorCode::NotAQuery});
    if (message.header.opcode != static_cast<uint8_t>(Opcode::Query))
        return std::unexpected(QueryError{QueryErrorCode::UnsupportedOpcode});
    if (message.header.authoritative_answer || message.header.truncated || message.header.recursion_available || message.header.reserved_z ||
        message.header.response_code != static_cast<uint8_t>(ResponseCode::NoError))
        return std::unexpected(QueryError{QueryErrorCode::InvalidHeaderFlags});
    if (message.questions.size() != 1)
        return std::unexpected(QueryError{QueryErrorCode::WrongQuestionCount});
    if (!message.answers.empty() || !message.authorities.empty())
        return std::unexpected(QueryError{QueryErrorCode::UnexpectedAnswerSection});
    if (!message.additionals.empty())
        return std::unexpected(QueryError{QueryErrorCode::ExtensionsNotSupported});

    const Question &question = message.questions.front();
    if (question.question_class != static_cast<uint16_t>(RecordClass::IN))
        return std::unexpected(QueryError{QueryErrorCode::UnsupportedClass});
    if (question.type != static_cast<uint16_t>(RecordType::A) && question.type != static_cast<uint16_t>(RecordType::AAAA))
        return std::unexpected(QueryError{QueryErrorCode::UnsupportedType});

    return question;
}

ResponseCode response_code_for(QueryErrorCode error) noexcept
{
    switch (error)
    {
        case QueryErrorCode::WrongQuestionCount:
        case QueryErrorCode::UnexpectedAnswerSection:
        case QueryErrorCode::InvalidHeaderFlags:
            return ResponseCode::FormErr;
        case QueryErrorCode::NotAQuery:
        case QueryErrorCode::UnsupportedOpcode:
        case QueryErrorCode::ExtensionsNotSupported:
        case QueryErrorCode::UnsupportedType:
        case QueryErrorCode::UnsupportedClass:
            return ResponseCode::NotImp;
    }

    return ResponseCode::ServFail;
}

} // namespace dns::protocol
