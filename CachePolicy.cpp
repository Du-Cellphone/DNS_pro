#include "CachePolicy.h"

#include <algorithm>
#include <array>
#include <limits>

namespace dns::server
{

std::optional<CacheableAddressSet> cacheable_address_set(const protocol::Message  &response,
                                                         const protocol::Question &expected_question)
{
    if (!response.header.is_response || response.header.truncated ||
        response.header.response_code != static_cast<uint8_t>(protocol::ResponseCode::NoError) || response.questions.size() != 1 ||
        !(response.questions.front() == expected_question) || response.answers.empty() ||
        response.answers.size() > std::numeric_limits<uint16_t>::max() || !response.authorities.empty() || !response.additionals.empty())
        return std::nullopt;

    CacheableAddressSet result;
    result.addresses.reserve(response.answers.size());
    result.ttl = std::numeric_limits<uint32_t>::max();

    for (const protocol::ResourceRecord &answer : response.answers)
    {
        if (!(answer.name == expected_question.name) || answer.type != expected_question.type ||
            answer.record_class != expected_question.question_class || answer.ttl == 0)
            return std::nullopt;

        if (answer.type == static_cast<uint16_t>(protocol::RecordType::A) && answer.rdata.size() == 4)
        {
            std::array<uint8_t, 4> bytes{};
            std::transform(answer.rdata.begin(), answer.rdata.end(), bytes.begin(), [](std::byte value) { return std::to_integer<uint8_t>(value); });
            result.addresses.push_back(Cache::IPAddress::v4(bytes));
        }
        else if (answer.type == static_cast<uint16_t>(protocol::RecordType::AAAA) && answer.rdata.size() == 16)
        {
            std::array<uint8_t, 16> bytes{};
            std::transform(answer.rdata.begin(), answer.rdata.end(), bytes.begin(), [](std::byte value) { return std::to_integer<uint8_t>(value); });
            result.addresses.push_back(Cache::IPAddress::v6(bytes));
        }
        else
        {
            return std::nullopt;
        }

        result.ttl = std::min(result.ttl, answer.ttl);
    }

    return result;
}

} // namespace dns::server
