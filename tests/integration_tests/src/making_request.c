#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include "../../../src/swift_net.h"
#include <stdatomic.h>
#include <unistd.h>
#include <stdlib.h>
#include "run_tests.h"

static _Atomic (struct SwiftNetClientConnection*) g_client_conn = NULL;
static _Atomic (struct SwiftNetServer*) g_server = NULL;

static _Atomic int g_test_result = INT_MAX;

static _Atomic (uint8_t*) g_request_data = NULL;
static _Atomic (uint8_t*) g_response_data = NULL;

static _Atomic bool g_sent_response = false; 

static _Atomic uint32_t g_request_data_len = 0;
static _Atomic uint32_t g_response_data_len = 0;

const uint8_t g_make_request_code = 0xFF;

static void wait_until_response_sent() {
    while (atomic_load_explicit(&g_sent_response, memory_order_acquire) == false) {
        usleep(1000);
    }
}

static void reset_test_state() {
    swiftnet_server_cleanup(atomic_load_explicit(&g_server, memory_order_acquire));
    swiftnet_client_cleanup(atomic_load_explicit(&g_client_conn, memory_order_acquire));

    uint8_t* response_data = atomic_load_explicit(&g_response_data, memory_order_acquire);
    uint8_t* request_data = atomic_load_explicit(&g_request_data, memory_order_acquire);

    if (response_data) free(response_data);
    if (request_data) free(request_data);

    atomic_store_explicit(&g_response_data, NULL, memory_order_release);
    atomic_store_explicit(&g_request_data, NULL, memory_order_release);

    atomic_store_explicit(&g_response_data_len, 0, memory_order_release);
    atomic_store_explicit(&g_request_data_len, 0, memory_order_release);

    atomic_store_explicit(&g_client_conn, NULL, memory_order_release);
    atomic_store_explicit(&g_server, NULL, memory_order_release);

    atomic_store_explicit(&g_sent_response, false, memory_order_release);

    atomic_store_explicit(&g_test_result, INT_MAX, memory_order_release);
}

static void on_client_packet(struct SwiftNetClientPacketData* packet, void* const user) {
    struct SwiftNetClientConnection* const client_conn = atomic_load_explicit(&g_client_conn, memory_order_acquire);

    if (packet->metadata.data_length != atomic_load_explicit(&g_request_data_len, memory_order_acquire)) {
        PRINT_ERROR("Server received invalid data size: %d | %d",
            packet->metadata.data_length,
            atomic_load_explicit(&g_request_data_len, memory_order_acquire)
        );

        atomic_store_explicit(&g_test_result, -1, memory_order_release);

        swiftnet_client_destroy_packet_data(packet, client_conn);

        return;
    }

    const uint8_t* data = atomic_load_explicit(&g_request_data, memory_order_acquire);

    for (uint32_t i = 0; i < packet->metadata.data_length; i++) {
        uint8_t byte_received = *(uint8_t*)swiftnet_client_read_packet(packet, 1);
        if (data[i] != byte_received) {
            PRINT_ERROR("Client received invalid data");

            atomic_store_explicit(&g_test_result, -1, memory_order_release);

            swiftnet_client_destroy_packet_data(packet, client_conn);
            
            return;
        }
    }

    const uint32_t response_data_len = atomic_load_explicit(&g_response_data_len, memory_order_acquire);
    uint8_t* response_data = atomic_load_explicit(&g_response_data, memory_order_acquire);

    struct SwiftNetPacketBuffer send_buffer = swiftnet_client_create_packet_buffer(response_data_len);

    swiftnet_client_append_to_packet(response_data, response_data_len, &send_buffer);

    swiftnet_client_make_response(atomic_load_explicit(&g_client_conn, memory_order_acquire), packet, &send_buffer);

    swiftnet_client_destroy_packet_buffer(&send_buffer);
    swiftnet_client_destroy_packet_data(packet, client_conn);

    atomic_store_explicit(&g_sent_response, true, memory_order_release);
}

static void on_server_packet(struct SwiftNetServerPacketData* packet, void* const user) {
    struct SwiftNetServer* const server = atomic_load_explicit(&g_server, memory_order_acquire);

    if (packet->metadata.expecting_response) {
        if (packet->metadata.data_length != atomic_load_explicit(&g_request_data_len, memory_order_acquire)) {
            PRINT_ERROR("Server received invalid data size: %d | %d",
                packet->metadata.data_length,
                atomic_load_explicit(&g_request_data_len, memory_order_acquire)
            );

            atomic_store_explicit(&g_test_result, -1, memory_order_release);

            swiftnet_server_destroy_packet_data(packet, server);

            return;
        }

        const uint8_t* data = atomic_load_explicit(&g_request_data, memory_order_acquire);

        for (uint32_t i = 0; i < packet->metadata.data_length; i++) {
            uint8_t byte_received = *(uint8_t*)swiftnet_server_read_packet(packet, 1);
            if (data[i] != byte_received) {
                PRINT_ERROR("Server received invalid data");

                atomic_store_explicit(&g_test_result, -1, memory_order_release);

                swiftnet_server_destroy_packet_data(packet, server);
                
                return;
            }
        }

        const uint32_t response_data_len = atomic_load_explicit(&g_response_data_len, memory_order_acquire);
        uint8_t* response_data = atomic_load_explicit(&g_response_data, memory_order_acquire);

        struct SwiftNetPacketBuffer send_buffer = swiftnet_server_create_packet_buffer(response_data_len);

        swiftnet_server_append_to_packet(response_data, response_data_len, &send_buffer);

        swiftnet_server_make_response(atomic_load_explicit(&g_server, memory_order_acquire), packet, &send_buffer);

        swiftnet_server_destroy_packet_buffer(&send_buffer);
        swiftnet_server_destroy_packet_data(packet, server);

        atomic_store_explicit(&g_sent_response, true, memory_order_release);
    } else {
        if (packet->metadata.data_length != sizeof(g_make_request_code)) {
            PRINT_ERROR("Server received invalid data size: %d | %lu",
                packet->metadata.data_length,
                sizeof(g_make_request_code)
            );

            atomic_store_explicit(&g_test_result, -1, memory_order_release);

            swiftnet_server_destroy_packet_data(packet, server);

            return;
        }

        uint8_t byte_received = *(uint8_t*)swiftnet_server_read_packet(packet, 1);

        if (byte_received != g_make_request_code) {
            PRINT_ERROR("Server received invalid data");

            atomic_store_explicit(&g_test_result, -1, memory_order_release);

            swiftnet_server_destroy_packet_data(packet, server);
            
            return;
        }

        const uint32_t request_data_len = atomic_load_explicit(&g_request_data_len, memory_order_acquire);
        uint8_t* request_data = atomic_load_explicit(&g_request_data, memory_order_acquire);
        const uint32_t response_data_len = atomic_load_explicit(&g_response_data_len, memory_order_acquire);
        uint8_t* response_data = atomic_load_explicit(&g_response_data, memory_order_acquire);

        struct SwiftNetPacketBuffer buffer = swiftnet_server_create_packet_buffer(request_data_len);

        swiftnet_server_append_to_packet(request_data, request_data_len, &buffer);

        struct SwiftNetServerPacketData* response = swiftnet_server_make_request(atomic_load_explicit(&g_server, memory_order_acquire), &buffer, packet->metadata.sender, 1000);

        swiftnet_server_destroy_packet_buffer(&buffer);

        if (response == NULL) {
            int result = atomic_load_explicit(&g_test_result, memory_order_acquire);
            if (result == INT_MAX) {
                swiftnet_server_destroy_packet_data(packet, server);

                return;
            }

            PRINT_ERROR("Did not receive response from server");

            atomic_store_explicit(&g_test_result, -1, memory_order_release);

            swiftnet_server_destroy_packet_data(packet, server);

            return;
        }

        if (response->metadata.data_length != response_data_len) {
            PRINT_ERROR("Server received invalid data size: %d | %d",
                response->metadata.data_length,
                response_data_len 
            );

            atomic_store_explicit(&g_test_result, -1, memory_order_release);

            swiftnet_server_destroy_packet_data(response, server);
            swiftnet_server_destroy_packet_data(packet, server);

            return;
         }

         for (uint32_t i = 0; i < response->metadata.data_length; i++) {
            uint8_t received_byte = *(uint8_t*)swiftnet_server_read_packet(response, 1);
            if (response_data[i] != received_byte) {
                PRINT_ERROR("Client received invalid data");

                atomic_store_explicit(&g_test_result, -1, memory_order_release);

                swiftnet_server_destroy_packet_data(response, server);
                swiftnet_server_destroy_packet_data(packet, server);

                return;
            }
        }

        atomic_store_explicit(&g_test_result, 0, memory_order_release);

        swiftnet_server_destroy_packet_data(response, server);
        swiftnet_server_destroy_packet_data(packet, server);
    }
}

int test_making_request(const union Args* args_ptr) {
    const struct TestMakingRequestArgs args = args_ptr->test_making_request_args;

    struct SwiftNetServer* const server = swiftnet_create_server(8080, args.loopback);
    if (server == NULL) {
        PRINT_ERROR("Failed to create server");
        return -1;
    }

    swiftnet_server_set_message_handler(server, on_server_packet, NULL);

    struct SwiftNetClientConnection* const client_conn = swiftnet_create_client(args.ip_address, 8080, 1000);
    if (client_conn == NULL) {
        PRINT_ERROR("Failed to create client connection");
        return -1;
    }

    swiftnet_client_set_message_handler(client_conn, on_client_packet, NULL);

    atomic_store_explicit(&g_client_conn, client_conn, memory_order_release);
    atomic_store_explicit(&g_server, server, memory_order_release);

    uint8_t* req_data = malloc(args.request_data_len);
    if (!req_data) {
        PRINT_ERROR("Failed to allocate memory");
        return -1;
    }

    uint8_t* res_data = malloc(args.response_data_len);
    if (!res_data) {
        PRINT_ERROR("Failed to allocate memory");
        return -1;
    }

    atomic_store_explicit(&g_request_data, req_data, memory_order_release);
    atomic_store_explicit(&g_response_data, res_data, memory_order_release);

    atomic_store_explicit(&g_request_data_len, args.request_data_len, memory_order_release);
    atomic_store_explicit(&g_response_data_len, args.response_data_len, memory_order_release);

    if (args.receiver == Server) {
        struct SwiftNetPacketBuffer buffer = swiftnet_client_create_packet_buffer(args.request_data_len);

        swiftnet_client_append_to_packet(req_data, args.request_data_len, &buffer);

        struct SwiftNetClientPacketData* const response = swiftnet_client_make_request(client_conn, &buffer, 1000);

        swiftnet_client_destroy_packet_buffer(&buffer);

        if (response == NULL) {
            int result = atomic_load_explicit(&g_test_result, memory_order_acquire);
            if (result != INT_MAX) {
                return result;
            }

            PRINT_ERROR("Did not receive response from server");

            reset_test_state();

            return -1;
        }

        if (response->metadata.data_length != args.response_data_len) {
            PRINT_ERROR("Client received invalid data size: %d | %d",
                response->metadata.data_length,
                args.response_data_len
            );

            swiftnet_client_destroy_packet_data(response, client_conn);

            reset_test_state();

            return -1;
        }

        for (uint32_t i = 0; i < response->metadata.data_length; i++) {
            uint8_t received_byte = *(uint8_t*)swiftnet_client_read_packet(response, 1);
            if (res_data[i] != received_byte) {
                PRINT_ERROR("Client received invalid data");

                swiftnet_client_destroy_packet_data(response, client_conn);

                reset_test_state();

                return -1;
            }
        }

        swiftnet_client_destroy_packet_data(response, client_conn);

        wait_until_response_sent();

        reset_test_state();

        return 0;
    } else {
        struct SwiftNetPacketBuffer buffer = swiftnet_client_create_packet_buffer(sizeof(g_make_request_code));

        swiftnet_client_append_to_packet(&g_make_request_code, sizeof(g_make_request_code), &buffer);

        swiftnet_client_send_packet(client_conn, &buffer);

        swiftnet_client_destroy_packet_buffer(&buffer);

        for ( ;; ) {
            int result = atomic_load_explicit(&g_test_result, memory_order_acquire);
            if (result == INT_MAX) {
                usleep(1000);
                continue;
            }

            if (result == 0) {
                wait_until_response_sent();
            }

            reset_test_state();

            return result;
        }
    }
}
