cmake_minimum_required(VERSION 3.23)
project(DNS_pro)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(DNS)

target_sources(DNS PUBLIC main.cpp DNS_Cache.cpp)

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_link_libraries(DNS PRIVATE -lstdc++exp)
    target_compile_options(DNS PRIVATE -fcoroutines)
    target_compile_options(DNS PRIVATE -msse4.2)
    target_compile_options(DNS PRIVATE -lpthread)
endif()