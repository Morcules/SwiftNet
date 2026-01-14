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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")

file(GLOB SRC_FILES "${CMAKE_SOURCE_DIR}/../src/*.c")

add_executable(run_tests ${SRC_FILES})

target_link_libraries(run_tests PRIVATE swiftnet -lpcap)
target_link_options(run_tests PRIVATE -g -O0)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
