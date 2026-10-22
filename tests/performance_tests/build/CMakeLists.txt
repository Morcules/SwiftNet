cmake_minimum_required(VERSION 3.15)
project(SwiftNetTests C)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../output)

if(SANITIZER STREQUAL "address")
    message(STATUS "Using AddressSanitizer")
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
elseif(SANITIZER STREQUAL "thread")
    message(STATUS "Using ThreadSanitizer")
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
elseif(SANITIZER STREQUAL "undefined")
    message(STATUS "Using UndefinedBehaviorSanitizer")
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined)
else()
    message(STATUS "No sanitizer enabled")
endif()

link_directories(${CMAKE_SOURCE_DIR}/../../../build/output)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

file(GLOB SRC_FILES "${CMAKE_SOURCE_DIR}/../src/*.c")

add_executable(run_tests ${SRC_FILES})

if(BACKEND STREQUAL "pcap")
add_compile_definitions(SWIFT_NET_BACKEND_PCAP)

target_link_libraries(run_tests PRIVATE -lpcap)

target_link_libraries(run_tests PRIVATE ${CMAKE_SOURCE_DIR}/../../../build/output/libswiftnet.a)
elseif(BACKEND STREQUAL "dpdk")
add_compile_definitions(SWIFT_NET_BACKEND_DPDK)

add_library(swiftnet STATIC IMPORTED)

set_target_properties(swiftnet PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../../../build/output/libswiftnet.a"
)

target_link_libraries(swiftnet INTERFACE
    rte_eal
    rte_ethdev
    rte_mbuf
    rte_mempool
    rte_ring
    rte_net
)

target_link_libraries(run_tests PRIVATE swiftnet)
endif()

target_link_options(run_tests PRIVATE -O3)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
