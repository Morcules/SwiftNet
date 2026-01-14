#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../src/swift_net.h"
#include "../../shared.h"


#define PACKET_SIZE 1000000 // 1 MILLION BYTES
#define PACKETS_TO_SEND 500 // HOW MANY PACKETS TO SEND

// ********************** //
// SEND 500 MILLION BYTES //
// ********************** //

char private_ip_address_testing[INET_ADDRSTRLEN];

static clock_t start;
static clock_t end;

static uint32_t packets_received = 0;

void packet_callback(struct SwiftNetServerPacketData* const packet_data, void* server) {
    packets_received++;

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

    struct SwiftNetPacketBuffer buffer = swiftnet_client_create_packet_buffer(PACKET_SIZE);

    uint8_t* const random_data = malloc(PACKET_SIZE);
    for (uint32_t i = 0; i < PACKET_SIZE; i++) {
        random_data[i] = rand();
    }

    swiftnet_client_append_to_packet(random_data, PACKET_SIZE, &buffer);

    start = clock();

    for (uint32_t i = 0; i < PACKETS_TO_SEND; i++) {
        swiftnet_client_send_packet(client, &buffer);
    }

    while (packets_received != PACKETS_TO_SEND) {
        usleep(100);
        continue;
    }

    swiftnet_client_destroy_packet_buffer(&buffer);

    end = clock();

    swiftnet_client_cleanup(client);
}

int main() {
    swiftnet_initialize();

    swiftnet_add_debug_flags(PACKETS_SENDING | PACKETS_RECEIVING | INITIALIZATION | LOST_PACKETS);

    send_large_packets(true);

    printf("Time to send: %f\n", (double)(end - start) / CLOCKS_PER_SEC);

    swiftnet_cleanup();

    return 0;
}
