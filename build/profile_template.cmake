add_compile_definitions(
    # SWIFT_NET_DISABLE_REQUESTS # Compile source without request features (make_request, make_response)
    SWIFT_NET_MEMORY_USAGE=5 # Multiplier of memory preallocated
)

set(SANITIZER "none") # (thread, address, undefined, none (no sanitizer))
set(BACKEND "pcap") # (pcap, dpdk)
