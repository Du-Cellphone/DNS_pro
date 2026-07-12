#pragma once

#include "HashUtils.hpp"
#include "protocol/DomainName.h"

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

class RadixTree
{
public:
    RadixTree();

    bool insert(const dns::protocol::DomainName &domain);
    bool insert(std::string_view domain);

    [[nodiscard]] bool search(const dns::protocol::DomainName &domain) const noexcept;
    [[nodiscard]] bool search(std::string_view domain) const;

private:
    struct TrieNode
    {
        std::unordered_map<std::string, std::unique_ptr<TrieNode>, SvCRC32, std::equal_to<>> children;
        bool                                                                                 is_end_of_domain{false};
    };

    std::unique_ptr<TrieNode> root_;
};
