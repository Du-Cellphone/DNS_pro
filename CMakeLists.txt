cmake_minimum_required(VERSION 3.23)

project(DNS_pro LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(DNS_PRO_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

find_package(Threads REQUIRED)
include(CTest)

function(dns_pro_set_warnings target)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    elseif(MSVC)
        target_compile_options(${target} PRIVATE /W4)
    endif()
endfunction()

function(dns_pro_enable_sanitizers target)
    if(NOT DNS_PRO_ENABLE_SANITIZERS)
        return()
    endif()

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    else()
        message(WARNING "DNS_PRO_ENABLE_SANITIZERS is only configured for GCC and Clang")
    endif()
endfunction()

add_library(dns_core STATIC
    CachePolicy.cpp
    DNS.cpp
    DNS_Cache.cpp
    CuckooFilter.cpp
    DomainBlocklist.cpp
    FilterContext.cpp
    protocol/DnsParser.cpp
    protocol/DnsQuery.cpp
    protocol/DnsResponse.cpp
    protocol/DnsWriter.cpp
    protocol/DomainName.cpp
    RadixTree.cpp
    runtime/Scheduler.cpp
    runtime/TimerQueue.cpp
    upstream/UpstreamChannel.cpp
    WorkerLoop.cpp
)

target_include_directories(dns_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(dns_core PUBLIC cxx_std_23)
target_link_libraries(dns_core PUBLIC Threads::Threads)
dns_pro_set_warnings(dns_core)
dns_pro_enable_sanitizers(dns_core)

add_executable(DNS main.cpp)
target_link_libraries(DNS PRIVATE dns_core)
dns_pro_set_warnings(DNS)
dns_pro_enable_sanitizers(DNS)

add_executable(filter_trie_benchmark tests/filter_trie_benchmark.cpp)
target_link_libraries(filter_trie_benchmark PRIVATE dns_core)
dns_pro_set_warnings(filter_trie_benchmark)
dns_pro_enable_sanitizers(filter_trie_benchmark)

if(BUILD_TESTING)
    add_executable(dns_component_tests tests/component_tests.cpp)
    target_link_libraries(dns_component_tests PRIVATE dns_core)
    dns_pro_set_warnings(dns_component_tests)
    dns_pro_enable_sanitizers(dns_component_tests)

    add_test(NAME dns_component_tests COMMAND dns_component_tests)
    set_tests_properties(dns_component_tests PROPERTIES TIMEOUT 10)

    add_executable(dns_protocol_tests tests/protocol_tests.cpp)
    target_link_libraries(dns_protocol_tests PRIVATE dns_core)
    dns_pro_set_warnings(dns_protocol_tests)
    dns_pro_enable_sanitizers(dns_protocol_tests)

    add_test(NAME dns_protocol_tests COMMAND dns_protocol_tests)
    set_tests_properties(dns_protocol_tests PROPERTIES TIMEOUT 10)

    add_executable(dns_filter_tests tests/filter_tests.cpp)
    target_link_libraries(dns_filter_tests PRIVATE dns_core)
    dns_pro_set_warnings(dns_filter_tests)
    dns_pro_enable_sanitizers(dns_filter_tests)
    add_test(NAME dns_filter_tests COMMAND dns_filter_tests)
    set_tests_properties(dns_filter_tests PROPERTIES TIMEOUT 10)

    add_executable(dns_cache_tests tests/cache_tests.cpp)
    target_link_libraries(dns_cache_tests PRIVATE dns_core)
    dns_pro_set_warnings(dns_cache_tests)
    dns_pro_enable_sanitizers(dns_cache_tests)
    add_test(NAME dns_cache_tests COMMAND dns_cache_tests)
    set_tests_properties(dns_cache_tests PROPERTIES TIMEOUT 10)

    add_executable(dns_cache_policy_tests tests/cache_policy_tests.cpp)
    target_link_libraries(dns_cache_policy_tests PRIVATE dns_core)
    dns_pro_set_warnings(dns_cache_policy_tests)
    dns_pro_enable_sanitizers(dns_cache_policy_tests)
    add_test(NAME dns_cache_policy_tests COMMAND dns_cache_policy_tests)
    set_tests_properties(dns_cache_policy_tests PROPERTIES TIMEOUT 10)

    add_executable(dns_lifecycle_tests tests/lifecycle_tests.cpp)
    target_link_libraries(dns_lifecycle_tests PRIVATE dns_core)
    dns_pro_set_warnings(dns_lifecycle_tests)
    dns_pro_enable_sanitizers(dns_lifecycle_tests)
    add_test(NAME dns_lifecycle_tests COMMAND dns_lifecycle_tests)
    set_tests_properties(dns_lifecycle_tests PROPERTIES TIMEOUT 10)

    add_executable(dns_reactor_tests tests/reactor_tests.cpp)
    target_link_libraries(dns_reactor_tests PRIVATE dns_core)
    dns_pro_set_warnings(dns_reactor_tests)
    dns_pro_enable_sanitizers(dns_reactor_tests)
    add_test(NAME dns_reactor_tests COMMAND dns_reactor_tests)
    set_tests_properties(dns_reactor_tests PROPERTIES TIMEOUT 10)

    add_executable(dns_runtime_tests tests/runtime_tests.cpp)
    target_link_libraries(dns_runtime_tests PRIVATE dns_core)
    dns_pro_set_warnings(dns_runtime_tests)
    dns_pro_enable_sanitizers(dns_runtime_tests)
    add_test(NAME dns_runtime_tests COMMAND dns_runtime_tests)
    set_tests_properties(dns_runtime_tests PROPERTIES TIMEOUT 10)

    add_executable(dns_timer_tests tests/timer_tests.cpp)
    target_link_libraries(dns_timer_tests PRIVATE dns_core)
    dns_pro_set_warnings(dns_timer_tests)
    dns_pro_enable_sanitizers(dns_timer_tests)
    add_test(NAME dns_timer_tests COMMAND dns_timer_tests)
    set_tests_properties(dns_timer_tests PROPERTIES TIMEOUT 10)

    add_executable(dns_upstream_tests tests/upstream_tests.cpp)
    target_link_libraries(dns_upstream_tests PRIVATE dns_core)
    dns_pro_set_warnings(dns_upstream_tests)
    dns_pro_enable_sanitizers(dns_upstream_tests)
    add_test(NAME dns_upstream_tests COMMAND dns_upstream_tests)
    set_tests_properties(dns_upstream_tests PROPERTIES TIMEOUT 10)
endif()
