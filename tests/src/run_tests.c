#include "run_tests.h"
#include "../../src/swift_net.h"
#include <stdint.h>
#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <netpacket/packet.h>
#include <net/if.h>
#elif defined(__APPLE__)
#include <net/if_dl.h>
#endif

static char private_ip_address[INET_ADDRSTRLEN];

int get_private_ip_from_socket() {
    const int temp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_socket < 0) {
        PRINT_ERROR("Failed to create temp socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in remote = {0};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr);

    if (connect(temp_socket, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        PRINT_ERROR("Failed to connect temp socket");
        close(temp_socket);
        exit(EXIT_FAILURE);
    }

    struct sockaddr private_sockaddr;
    socklen_t private_sockaddr_len = sizeof(private_sockaddr);

    if(getsockname(temp_socket, &private_sockaddr, &private_sockaddr_len) == -1) {
        PRINT_ERROR("Failed to get private ip address");
        close(temp_socket);
        exit(EXIT_FAILURE);
    }

    if(!inet_ntop(AF_INET, &((struct sockaddr_in *)&private_sockaddr)->sin_addr, private_ip_address, sizeof(private_ip_address))) {
        exit(EXIT_FAILURE);
    };

    printf("Private ip: %s\n", private_ip_address);

    return 0;
}

int main() {
    get_private_ip_from_socket();

    const struct Test tests[] = {
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
        // local default interface test
        {
            .function = test_sending_packet,
            .args = {.test_sending_packet_args = {
                .client_data_len = 50,
                .server_data_len = 50,
                .ip_address = private_ip_address,
                .loopback = false
            }},
            .test_name = "Test sending small packets"
        },
        {
            .function = test_sending_packet,
            .args = {.test_sending_packet_args = {
                .client_data_len = 0,
                .server_data_len = 10000,
                .ip_address = private_ip_address,
                .loopback = false
            }},
            .test_name = "Test client sending large packet"
        },
        {
            .function = test_sending_packet,
            .args = {.test_sending_packet_args = {
                .client_data_len = 10000,
                .server_data_len = 10,
                .ip_address = private_ip_address,
                .loopback = false
            }},
            .test_name = "Test server sending large packet"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = private_ip_address,
                .loopback = false,
                .receiver = Server,
                .request_data_len = 100,
                .response_data_len = 100
            }},
            .test_name = "Test client making small request"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = private_ip_address,
                .loopback = false,
                .receiver = Client,
                .request_data_len = 100,
                .response_data_len = 100
            }},
            .test_name = "Test server making small request"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = private_ip_address,
                .loopback = false,
                .receiver = Client,
                .request_data_len = 10000,
                .response_data_len = 100
            }},
            .test_name = "Test server making large request"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = private_ip_address,
                .loopback = false,
                .receiver = Server,
                .request_data_len = 10000,
                .response_data_len = 100
            }},
            .test_name = "Test client making large request"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = private_ip_address,
                .loopback = false,
                .receiver = Client,
                .request_data_len = 100,
                .response_data_len = 10000
            }},
            .test_name = "Test client making large response"
        },
        {
            .function = test_making_request,
            .args = {.test_making_request_args = {
                .ip_address = private_ip_address,
                .loopback = false,
                .receiver = Server,
                .request_data_len = 100,
                .response_data_len = 10000
            }},
            .test_name = "Test server making large response"
        },
    };

    swiftnet_initialize();

    swiftnet_add_debug_flags(DEBUG_INITIALIZATION | DEBUG_LOST_PACKETS | DEBUG_PACKETS_RECEIVING | DEBUG_PACKETS_SENDING);

    for (uint16_t i = 0; i < sizeof(tests) / sizeof(struct Test); i++) {
        const struct Test* current_test = &tests[i];

        int result = current_test->function(&current_test->args);
        if (result != 0) {
            PRINT_ERROR("Failed test: %s", current_test->test_name);

            swiftnet_cleanup();

            return -1;
        }

        printf("\033[32mSuccessfully completed test: %s\033[0m\n", current_test->test_name);

        continue;
    }

    swiftnet_cleanup();

    return 0;
}
