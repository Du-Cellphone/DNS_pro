#include "CuckooFilter.h"
#include "HashUtils.hpp"
#include "RadixTree.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

namespace
{

void require(bool condition, std::string_view message)
{
    if (condition)
        return;

    std::cerr << "component test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

void test_hashes_accept_unaligned_input()
{
    const std::string storage = "#www.example.com";
    const std::string_view unaligned{storage.data() + 1, storage.size() - 1};
    const std::string aligned{unaligned};

    require(SvCRC32{}(unaligned) == SvCRC32{}(aligned), "SvCRC32 must not depend on input alignment");
    require(XXH3_64{}(unaligned) == XXH3_64{}(aligned), "XXH3 must not depend on input alignment");
    require(xxH3_64bits(unaligned) == xxH3_64bits(aligned), "XXH3 helper must hash the complete string_view");
}

void test_cuckoo_filter_smoke()
{
    Filter::CuckooFilter filter{64};

    require(filter.insert("example.com"), "CuckooFilter insertion must succeed in an empty filter");
    require(filter.contains("example.com"), "CuckooFilter must find an inserted domain");
    require(filter.get_size() == 1, "duplicate-free insertion must update the filter size");

    require(filter.insert("example.com"), "duplicate CuckooFilter insertion must be idempotent");
    require(filter.get_size() == 1, "duplicate insertion must not change the filter size");
}

void test_radix_tree_parent_domain_semantics()
{
    RadixTree tree;
    tree.insert("example.com");

    require(tree.search("example.com"), "RadixTree must match an exact domain");
    require(tree.search("www.example.com"), "RadixTree must match a child of an inserted parent domain");
    require(!tree.search("example.net"), "RadixTree must reject an unrelated domain");
}

} // namespace

int main()
{
    test_hashes_accept_unaligned_input();
    test_cuckoo_filter_smoke();
    test_radix_tree_parent_domain_semantics();

    std::cout << "all component tests passed\n";
    return EXIT_SUCCESS;
}
