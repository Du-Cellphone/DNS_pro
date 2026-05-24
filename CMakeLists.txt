cmake_minimum_required(VERSION 3.23)
project(DNS_pro)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(DNS)

target_sources(DNS PUBLIC DNS.cpp main.cpp DNS_Cache.cpp CuckooFilter.cpp)

add_executable(filter_trie_benchmark)

target_sources(filter_trie_benchmark PRIVATE
    tests/filter_trie_benchmark.cpp
    CuckooFilter.cpp
    RadixTree.cpp
)

target_compile_features(filter_trie_benchmark PRIVATE cxx_std_23)

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_link_libraries(DNS PRIVATE -lstdc++exp)
    target_compile_options(DNS PRIVATE -fcoroutines)
    target_compile_options(DNS PRIVATE -msse4.2)
    target_compile_options(DNS PRIVATE -lpthread)
    target_compile_options(filter_trie_benchmark PRIVATE -msse4.2)
    target_compile_options(filter_trie_benchmark PRIVATE -march=native)
    target_compile_options(filter_trie_benchmark PRIVATE -O2)
endif()