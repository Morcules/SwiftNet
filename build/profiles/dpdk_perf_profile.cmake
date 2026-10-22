set(CMAKE_BUILD_TYPE Release)

add_compile_definitions(
    SWIFT_NET_MEMORY_USAGE=5
    DPDK_LCORES=1
)

set(SWIFT_NET_INTERNAL_TESTING OFF)
set(SANITIZER "none")
set(BACKEND "dpdk")
set(DPDK_EXTRA_ARGS "--no-pci, --vdev=net_ring0") # Basic loopback setup
