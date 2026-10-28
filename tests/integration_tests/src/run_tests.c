#include "run_tests.h"
#include "../../../src/swift_net.h"
#include <stdint.h>
#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "../../shared.h"

char private_ip_address_testing[INET_ADDRSTRLEN];

#if defined(__APPLE__) || defined(__linux__)
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#elif defined(_WIN32)
#endif

int main(void) {
    swiftnet_initialize();
    swiftnet_add_debug_flags(SWIFTNET_DEBUG_FLAGS(SWIFTNET_DEBUG_PACKETS_SENDING | SWIFTNET_DEBUG_PACKETS_RECEIVING | SWIFTNET_DEBUG_INITIALIZATION | SWIFTNET_DEBUG_LOST_PACKETS));

    get_private_ip_from_socket();

    struct Test tests[] = {
        // Loopback tests
        {
            .function = test_sending_packet,
            .args = {.test_sending_packet_args = {
                .client_data_len = 50,
                .server_data_len = 50,
                .ip_address = "127.0.0.1",
                .loopback = true
            }},
            .test_name = "Test sending small packets"
        },
        {
            .function = test_sending_packet,
            .args = {.test_sending_packet_args = {
                .client_data_len = 0,
                .server_data_len = 10000,
                .ip_address = "127.0.0.1",
                .loopback = true
            }},
            .test_name = "Test client sending large packet"
        },
        {
            .function = test_sending_packet,
            .args = {.test_sending_packet_args = {
                .client_data_len = 10000,
                .server_data_len = 10,
                .ip_address = "127.0.0.1",
                .loopback = true
            }},
            .test_name = "Test server sending large packet"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = "127.0.0.1",
                .loopback = true,
                .receiver = Server,
                .request_data_len = 100,
                .response_data_len = 100
            }},
            .test_name = "Test client making small request"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = "127.0.0.1",
                .loopback = true,
                .receiver = Client,
                .request_data_len = 100,
                .response_data_len = 100
            }},
            .test_name = "Test server making small request"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = "127.0.0.1",
                .loopback = true,
                .receiver = Client,
                .request_data_len = 10000,
                .response_data_len = 100
            }},
            .test_name = "Test server making large request"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = "127.0.0.1",
                .loopback = true,
                .receiver = Server,
                .request_data_len = 10000,
                .response_data_len = 100
            }},
            .test_name = "Test client making large request"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = "127.0.0.1",
                .loopback = true,
                .receiver = Client,
                .request_data_len = 100,
                .response_data_len = 10000
            }},
            .test_name = "Test client making large response"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = "127.0.0.1",
                .loopback = true,
                .receiver = Server,
                .request_data_len = 100,
                .response_data_len = 10000
            }},
            .test_name = "Test server making large response"
        },
    };

    for (uint16_t i = 0; i < sizeof(tests) / sizeof(struct Test); i++) {
        const struct Test* current_test = &tests[i];

        int result = current_test->function(&current_test->args);
        if (result != 0) {
            PRINT_ERROR("Failed test: %s", current_test->test_name);

            swiftnet_cleanup();

            return -1;
        }

        PRINT_SUCCESS("Successfully completed test: %s", current_test->test_name);

        continue;
    }


    // Test default network interface only on macos, because it works without any setup
    #if defined(__APPLE__) || defined(_WIN32)
    for (uint16_t i = 0; i < sizeof(tests) / sizeof(struct Test); i++) {
        struct Test* current_test = &tests[i];
        if (current_test->function == test_making_request) {
            current_test->args.test_making_request_args.loopback = false;
            current_test->args.test_making_request_args.ip_address = private_ip_address_testing;
        } else if (current_test->function == test_sending_packet) {
            current_test->args.test_sending_packet_args.loopback = false;
            current_test->args.test_sending_packet_args.ip_address = private_ip_address_testing;
        }

        int result = current_test->function(&current_test->args);
        if (result != 0) {
            PRINT_ERROR("Failed test: %s", current_test->test_name);

            swiftnet_cleanup();

            return -1;
        }

        PRINT_SUCCESS("Successfully completed test: %s", current_test->test_name);

        continue;
    }
    #endif

    swiftnet_cleanup();

    return 0;
}
