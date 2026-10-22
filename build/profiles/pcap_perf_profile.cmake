set(CMAKE_BUILD_TYPE Release)

add_compile_definitions(
    SWIFT_NET_MEMORY_USAGE=5
)

set(SWIFT_NET_INTERNAL_TESTING OFF)
set(SANITIZER "none")
set(BACKEND "pcap")
