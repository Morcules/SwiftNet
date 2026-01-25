cmake_minimum_required(VERSION 3.10)
project(swiftnet C CXX)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 99)

option(SWIFT_NET_INTERNAL_TESTING "Enable internal testing features" OFF)

set(SOURCE_FILES
    initialize_swiftnet.c
    send_packet.c
    handle_packets.c
    generic_functions.c
    initialize_client_connection.c
    initialize_server.c
    cleanup_connection.c
    process_packets.c
    execute_packet_callback.c
    packet_buffer.c
    manipulate_debug_flags.c
    cleanup_swiftnet.c
    make_response.c
    make_request.c
    internal/get_mtu.c
    internal/get_default_interface_and_mac.c
    internal/datatype_allocator.c
    internal/datatype_vector.c
    internal/pcap_open.c
    internal/pcap_send.c
    internal/check_existing_listener.c
)

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

add_library(swiftnet STATIC ${SOURCE_FILES})

if (SWIFT_NET_INTERNAL_TESTING)
    message("Internal Testing Enabled")

    add_compile_definitions(SWIFT_NET_INTERNAL_TESTING)

    target_compile_options(swiftnet PRIVATE -O0)
    target_link_options(swiftnet PRIVATE -O0)
else()
    message("Internal Testing Disabled")

    target_compile_options(swiftnet PRIVATE -O3)
    target_link_options(swiftnet PRIVATE -O3)
endif()

if(DEFINED ENV{VCPKG_ROOT} AND DEFINED CMAKE_VCPKG_TARGET_TRIPLET)
    set(VCPKG_INCLUDE_DIR "$ENV{VCPKG_ROOT}/installed/${CMAKE_VCPKG_TARGET_TRIPLET}/include")
    set(VCPKG_LIB_DIR "$ENV{VCPKG_ROOT}/installed/${CMAKE_VCPKG_TARGET_TRIPLET}/lib")

    find_path(PCAP_INCLUDE_DIR pcap.h
        PATHS ${VCPKG_INCLUDE_DIR} /usr/include /usr/local/include /opt/homebrew/include
    )
    find_library(PCAP_LIBRARY pcap
        PATHS ${VCPKG_LIB_DIR} /usr/lib /usr/local/lib /opt/homebrew/lib
    )

    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        message(STATUS "libpcap found: ${PCAP_LIBRARY}")
        target_include_directories(swiftnet PUBLIC ${PCAP_INCLUDE_DIR})
        target_link_libraries(swiftnet PUBLIC ${PCAP_LIBRARY})
    else()
        message(WARNING "libpcap not found!!!")
    endif()
else()
    target_link_options(swiftnet PRIVATE -lpcap)

    message("using linking option: -lpcap")
endif()

set_target_properties(swiftnet PROPERTIES
    OUTPUT_NAME "swiftnet"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/output"
    PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/swift_net.h"
)

add_custom_target(clean_objects
    COMMAND ${CMAKE_COMMAND} -E rm -f ${OBJ_DIR}/output/*.o
    COMMENT "Cleaning up object files"
)

install(TARGETS swiftnet
    EXPORT swiftnetTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include
    CONFIGURATIONS Release RelWithDebInfo MinSizeRel
)

install(EXPORT swiftnetTargets
    FILE swiftnetTargets.cmake
    NAMESPACE swiftnet::
    DESTINATION share/morcules-swiftnet
    CONFIGURATIONS Release RelWithDebInfo MinSizeRel
)

include(CMakePackageConfigHelpers)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/cmake)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/morcules-swiftnetConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cmake/morcules-swiftnetConfig.cmake
    INSTALL_DESTINATION share/morcules-swiftnet
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/cmake/morcules-swiftnetConfigVersion.cmake
    VERSION 0.2.0
    COMPATIBILITY AnyNewerVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cmake/morcules-swiftnetConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/cmake/morcules-swiftnetConfigVersion.cmake
    DESTINATION share/morcules-swiftnet
    CONFIGURATIONS Release RelWithDebInfo MinSizeRel
)
