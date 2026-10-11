set(CMAKE_BUILD_TYPE Debug)

add_compile_definitions(
    # SWIFT_NET_DISABLE_REQUESTS # Compile source without request features (make_request, make_response)
    SWIFT_NET_MEMORY_USAGE=5 # Multiplier of memory preallocated

    # DPDK SPECIFIC SETTINGS
    DPDK_LCORES=1 # List of cores to use for DPDK (every unique interface used requires one lcore)
)

set(SWIFT_NET_INTERNAL_TESTING ON) # Only used when debugging the library itself
set(SANITIZER "none") # (thread, address, undefined, none (no sanitizer))
set(BACKEND "") # (pcap, dpdk)
# DPDK SPECIFIC SETTINGS
set(DPDK_EXTRA_ARGS "") # Extra DPDK args
