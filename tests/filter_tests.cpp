#include "CuckooFilter.h"
#include "DomainBlocklist.h"
#include "RadixTree.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "filter test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

void test_cuckoo_failed_kick_is_atomic()
{
    Filter::CuckooFilter filter{8, 1};
    std::vector<std::string> inserted;
    bool observed_kick_failure = false;

    for (size_t index = 0; index < 10'000; ++index)
    {
        std::string key = "rule-" + std::to_string(index) + ".example";
        const size_t size_before = filter.get_size();
        if (filter.insert(key))
        {
            inserted.push_back(std::move(key));
            continue;
        }

        require(filter.get_size() == size_before, "a failed insertion must not change size");
        for (const std::string &old_key : inserted)
            require(filter.contains(old_key), "a failed kick chain must not lose an existing fingerprint");

        if (filter.last_failure() == Filter::InsertFailureReason::KickLimit)
        {
            observed_kick_failure = true;
            break;
        }
        require(filter.last_failure() != Filter::InsertFailureReason::LoadLimit,
                "the deterministic fixture should reach a kick failure before the load ceiling");
    }

    require(observed_kick_failure, "the fixture must exercise transactional kick rollback");
}

void test_radix_tree_is_canonical_and_const_safe()
{
    RadixTree tree;
    require(tree.insert("Example.COM."), "the first canonical rule insertion must succeed");
    require(!tree.insert("example.com"), "a duplicate canonical rule must be idempotent");

    const RadixTree &read_only_tree = tree;
    require(read_only_tree.search("WWW.EXAMPLE.COM."), "a parent rule must match a canonicalized child");
    require(!read_only_tree.search("badexample.com"), "label boundaries must prevent suffix-string false matches");
    require(!read_only_tree.search("example.net"), "an unrelated domain must not match");
}

void test_domain_blocklist_pipeline_semantics()
{
    const std::vector<std::string> rules{"Example.COM.", "www.specific.test", "example.com"};
    auto blocklist = Filter::DomainBlocklist::build(rules);
    require(blocklist.has_value(), "valid rules must build a blocklist snapshot");
    require(blocklist->rule_count() == 2, "canonical duplicate rules must be removed");

    require(blocklist->matches("example.com"), "an exact rule must match");
    require(blocklist->matches("www.api.example.com"), "the prefilter must not hide a parent-domain match");
    require(blocklist->matches("WWW.EXAMPLE.COM."), "query normalization must match rule normalization");
    require(!blocklist->matches("specific.test"), "a child rule must not match its parent");
    require(!blocklist->matches("badexample.com"), "a sibling suffix must not match");
    require(!blocklist->matches("example.net"), "an unrelated query must not match");

    const std::vector<std::string> wildcard{"*.example.com"};
    auto wildcard_result = Filter::DomainBlocklist::build(wildcard);
    require(!wildcard_result && wildcard_result.error().code == Filter::BlocklistBuildErrorCode::WildcardNotSupported,
            "MVP wildcard rules must be rejected explicitly");

    const std::vector<std::string> invalid{"example..com"};
    auto invalid_result = Filter::DomainBlocklist::build(invalid);
    require(!invalid_result && invalid_result.error().code == Filter::BlocklistBuildErrorCode::InvalidDomain,
            "invalid rule names must reject the whole snapshot");

    const std::vector<std::string> root{"."};
    auto root_result = Filter::DomainBlocklist::build(root);
    require(!root_result && root_result.error().code == Filter::BlocklistBuildErrorCode::RootRuleNotAllowed,
            "a root rule must not accidentally block all DNS traffic");
}

} // namespace

int main()
{
    test_cuckoo_failed_kick_is_atomic();
    test_radix_tree_is_canonical_and_const_safe();
    test_domain_blocklist_pipeline_semantics();
    std::cout << "all filter tests passed\n";
    return EXIT_SUCCESS;
}
