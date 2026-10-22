#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../src/swift_net.h"
#include "../../shared.h"

#define LOOPBACK true
#define PACKET_SIZE 10000000 // 10 MILLION BYTES
#define PACKETS_TO_SEND 10 // HOW MANY PACKETS TO SEND

// ********************** //
// SEND 100 MILLION BYTES //
// ********************** //

char private_ip_address_testing[INET_ADDRSTRLEN];

static struct timespec start, end;

static uint32_t packets_received = 0;
static _Atomic bool finished = false;
static uint8_t* data_to_send;

void packet_callback(struct SwiftNetServerPacketData* const packet_data, void* server) {
    packets_received++;

    if (packets_received == PACKETS_TO_SEND) {
        atomic_store_explicit(&finished, true, memory_order_release);
    }

    swiftnet_server_destroy_packet_data(packet_data, server);
}

void send_large_packets(const bool loopback) {
    struct SwiftNetServer* const server = swiftnet_create_server(8080, loopback);
    if (server == NULL) {
        PRINT_ERROR("FAILED TO INIT SERVER");
        swiftnet_cleanup();
        exit(EXIT_FAILURE);
    }
    
    swiftnet_server_set_message_handler(server, packet_callback, server);

    struct SwiftNetClientConnection* const client = swiftnet_create_client(loopback ? "127.0.0.1" : private_ip_address_testing, 8080, 1000);
    if (client == NULL) {
        PRINT_ERROR("FAILED TO INIT CLIENT");
        swiftnet_server_cleanup(server);
        swiftnet_cleanup();
        exit(EXIT_FAILURE);
    }

    struct SwiftNetPacketBuffer buffer = swiftnet_client_create_packet_buffer(PACKET_SIZE, client);

    data_to_send = malloc(PACKET_SIZE);
    if(data_to_send == NULL) {
	exit(EXIT_FAILURE);
    }

    swiftnet_append_to_buffer(data_to_send, PACKET_SIZE, &buffer);

    clock_gettime(CLOCK_MONOTONIC, &start);;

    for (uint32_t i = 0; i < PACKETS_TO_SEND; i++) {
        swiftnet_client_send_packet(client, &buffer, PACKET_SIZE);
    }

    while (atomic_load_explicit(&finished, memory_order_acquire) == false) {
        continue;
    }

    swiftnet_client_destroy_packet_buffer(&buffer, client);

    clock_gettime(CLOCK_MONOTONIC, &end);;

    usleep(100000);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    PRINT_SUCCESS("Time to send: %.2f seconds", elapsed);
    PRINT_SUCCESS("Bytes per second: %.2f", (PACKETS_TO_SEND * PACKET_SIZE) / elapsed)

    swiftnet_client_cleanup(client);
}

int main(void) {
    swiftnet_initialize();

    send_large_packets(LOOPBACK);

    swiftnet_cleanup();

    return 0;
}
