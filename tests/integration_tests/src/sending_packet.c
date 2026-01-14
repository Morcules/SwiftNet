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

static _Atomic bool g_client_send_done = false;
static _Atomic bool g_server_send_done = false;
static _Atomic int g_test_result = INT_MAX;

static _Atomic (uint8_t*) g_client_data = NULL;
static _Atomic (uint8_t*) g_server_data = NULL;

static _Atomic uint32_t g_client_data_len = 0;
static _Atomic uint32_t g_server_data_len = 0;

static void reset_test_state() {
    swiftnet_server_cleanup(atomic_load_explicit(&g_server, memory_order_acquire));
    swiftnet_client_cleanup(atomic_load_explicit(&g_client_conn, memory_order_acquire));

    uint8_t* client_data = atomic_load_explicit(&g_client_data, memory_order_acquire);
    uint8_t* server_data = atomic_load_explicit(&g_server_data, memory_order_acquire);

    if (client_data) free(client_data);
    if (server_data) free(server_data);

    atomic_store_explicit(&g_client_send_done, false, memory_order_release);
    atomic_store_explicit(&g_server_send_done, false, memory_order_release);

    atomic_store_explicit(&g_client_data, NULL, memory_order_release);
    atomic_store_explicit(&g_server_data, NULL, memory_order_release);

    atomic_store_explicit(&g_client_data_len, 0, memory_order_release);
    atomic_store_explicit(&g_server_data_len, 0, memory_order_release);

    atomic_store_explicit(&g_client_conn, NULL, memory_order_release);
    atomic_store_explicit(&g_server, NULL, memory_order_release);

    atomic_store_explicit(&g_test_result, INT_MAX, memory_order_release);
}

static void on_client_packet(struct SwiftNetClientPacketData* packet, void* const user) {
    struct SwiftNetClientConnection* const client_conn = atomic_load_explicit(&g_client_conn, memory_order_acquire);

    while (!atomic_load_explicit(&g_client_send_done, memory_order_acquire)) usleep(1000);

    if (packet->metadata.data_length != atomic_load_explicit(&g_client_data_len, memory_order_acquire)) {
        PRINT_ERROR("Client received invalid data size: %d | %d",
            packet->metadata.data_length,
            atomic_load_explicit(&g_client_data_len, memory_order_acquire)
        );

        atomic_store_explicit(&g_test_result, -1, memory_order_release);

        swiftnet_client_destroy_packet_data(packet, client_conn);

        return;
    }

    const uint8_t* data = atomic_load_explicit(&g_client_data, memory_order_acquire);

    for (uint32_t i = 0; i < packet->metadata.data_length; i++) {
        uint8_t received_byte = *(uint8_t*)swiftnet_client_read_packet(packet, 1);
        if (data[i] != received_byte) {
            PRINT_ERROR("Client received invalid data");

            atomic_store_explicit(&g_test_result, -1, memory_order_release);

            swiftnet_client_destroy_packet_data(packet, client_conn);

            return;
        }
    }

    atomic_store_explicit(&g_test_result, 0, memory_order_release);

    swiftnet_client_destroy_packet_data(packet, client_conn);
}

static void on_server_packet(struct SwiftNetServerPacketData* packet, void* const user) {
    struct SwiftNetServer* const server = atomic_load_explicit(&g_server, memory_order_acquire);

    while (!atomic_load_explicit(&g_server_send_done, memory_order_acquire)) usleep(1000);

    if (packet->metadata.data_length != atomic_load_explicit(&g_server_data_len, memory_order_acquire)) {
        PRINT_ERROR("Server received invalid data size: %d | %d",
            packet->metadata.data_length,
            atomic_load_explicit(&g_server_data_len, memory_order_acquire)
        );

        atomic_store_explicit(&g_test_result, -1, memory_order_release);

        swiftnet_server_destroy_packet_data(packet, server);

        return;
    }

    const uint8_t* data = atomic_load_explicit(&g_server_data, memory_order_acquire);

    for (uint32_t i = 0; i < packet->metadata.data_length; i++) {
        uint8_t byte_received = *(uint8_t*)swiftnet_server_read_packet(packet, 1);
        if (data[i] != byte_received) {
            PRINT_ERROR("Server received invalid data");

            atomic_store_explicit(&g_test_result, -1, memory_order_release);

            swiftnet_server_destroy_packet_data(packet, server);

            return;
        }
    }

    if (atomic_load_explicit(&g_client_data_len, memory_order_acquire) != 0) {
        uint32_t size = atomic_load_explicit(&g_client_data_len, memory_order_acquire);
        uint8_t* send_data = atomic_load_explicit(&g_client_data, memory_order_acquire);

        struct SwiftNetPacketBuffer buf = swiftnet_server_create_packet_buffer(size);
        swiftnet_server_append_to_packet(send_data, size, &buf);
        swiftnet_server_send_packet(atomic_load_explicit(&g_server, memory_order_acquire), &buf, packet->metadata.sender);
        swiftnet_server_destroy_packet_buffer(&buf);

        atomic_store_explicit(&g_client_send_done, true, memory_order_release);
    } else {
        atomic_store_explicit(&g_test_result, 0, memory_order_release);
    }

    swiftnet_server_destroy_packet_data(packet, server);
}

int test_sending_packet(const union Args* args_ptr) {
    const struct TestSendingPacketArgs args = args_ptr->test_sending_packet_args;

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

    g_client_data_len = args.client_data_len;
    g_server_data_len = args.server_data_len;

    uint8_t* c_data = malloc(args.client_data_len);
    if (!c_data) {
        PRINT_ERROR("Failed to allocate memory");
        return -1;
    }

    for (uint32_t i = 0; i < args.client_data_len; i++) c_data[i] = rand();

    atomic_store_explicit(&g_client_data, c_data, memory_order_release);

    if (args.server_data_len != 0) {
        uint8_t* s_data = malloc(args.server_data_len);
        if (!s_data) {
            PRINT_ERROR("Failed to allocate memory");
            return -1;
        }

        for (uint32_t i = 0; i < args.server_data_len; i++) s_data[i] = rand();

        atomic_store_explicit(&g_server_data, s_data, memory_order_release);
    }

    struct SwiftNetPacketBuffer buf = swiftnet_client_create_packet_buffer(args.server_data_len);
    swiftnet_client_append_to_packet(atomic_load_explicit(&g_server_data, memory_order_acquire), args.server_data_len, &buf);
    swiftnet_client_send_packet(client_conn, &buf);
    swiftnet_client_destroy_packet_buffer(&buf);

    atomic_store_explicit(&g_server_send_done, true, memory_order_release);

    for ( ;; ) {
        int result = atomic_load_explicit(&g_test_result, memory_order_acquire);
        if (result == INT_MAX) {
            usleep(1000);
            continue;
        }
        reset_test_state();
        return result;
    }
}
