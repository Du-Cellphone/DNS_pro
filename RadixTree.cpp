#include "RadixTree.h"

#include <utility>

RadixTree::RadixTree()
    : root_(std::make_unique<TrieNode>())
{
}

bool RadixTree::insert(const dns::protocol::DomainName &domain)
{
    TrieNode *current = root_.get();
    const auto labels = domain.labels();

    for (size_t reverse_index = labels.size(); reverse_index > 0; --reverse_index)
    {
        const std::string_view canonical_label = domain.canonical_label(reverse_index - 1);
        auto [child, inserted] = current->children.try_emplace(std::string{canonical_label});
        if (inserted)
            child->second = std::make_unique<TrieNode>();
        current = child->second.get();
    }

    const bool newly_inserted = !current->is_end_of_domain;
    current->is_end_of_domain = true;
    return newly_inserted;
}

bool RadixTree::insert(std::string_view domain)
{
    auto normalized = dns::protocol::DomainName::from_text(domain);
    return normalized && insert(*normalized);
}

bool RadixTree::search(const dns::protocol::DomainName &domain) const noexcept
{
    const TrieNode *current = root_.get();
    const auto      labels  = domain.labels();

    for (size_t reverse_index = labels.size(); reverse_index > 0; --reverse_index)
    {
        const std::string_view canonical_label = domain.canonical_label(reverse_index - 1);
        const auto child = current->children.find(canonical_label);
        if (child == current->children.end())
            return false;
        current = child->second.get();
        if (current->is_end_of_domain)
            return true;
    }

    return current->is_end_of_domain;
}

bool RadixTree::search(std::string_view domain) const
{
    auto normalized = dns::protocol::DomainName::from_text(domain);
    return normalized && search(*normalized);
}
