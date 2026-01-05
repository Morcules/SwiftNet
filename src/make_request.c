#include "internal/internal.h"
#include "swift_net.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#ifdef SWIFT_NET_REQUESTS

static inline void delete_request_sent(struct RequestSent* request_sent) {
    vector_lock(&requests_sent);

    for (uint32_t i = 0; i < requests_sent.size; i++) {
        if (vector_get(&requests_sent, i) == request_sent) {
            vector_remove(&requests_sent, i);
        }
    }

    vector_unlock(&requests_sent);

    allocator_free(&requests_sent_memory_allocator, request_sent);
}

static inline struct RequestSent* const construct_request_sent(const struct in_addr address) {
    struct RequestSent* const request_sent = allocator_allocate(&requests_sent_memory_allocator);
    request_sent->packet_data = NULL;
    request_sent->address = address;

    return request_sent;
}

struct SwiftNetClientPacketData* swiftnet_client_make_request(struct SwiftNetClientConnection* const client, struct SwiftNetPacketBuffer* const packet, const uint32_t timeout_ms) {
    struct RequestSent* const request_sent = construct_request_sent(client->server_addr);

    const uint32_t packet_length = packet->packet_append_pointer - packet->packet_data_start;

    swiftnet_send_packet(client, client->maximum_transmission_unit, client->port_info, packet, packet_length, &client->server_addr, &client->packets_sending, &client->packets_sending_memory_allocator, client->pcap, client->eth_header, client->loopback, client->addr_type, client->prepend_size, request_sent, false, 0);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t start = (uint32_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

    while (1) {
        gettimeofday(&tv, NULL);
        uint32_t end = (uint32_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

        if (start + timeout_ms < end) {
            delete_request_sent(request_sent);

            return NULL;
        }

        if (atomic_load_explicit(&request_sent->packet_data, memory_order_acquire) != NULL) {
            struct SwiftNetClientPacketData* const packet_data = request_sent->packet_data;

            allocator_free(&requests_sent_memory_allocator, request_sent);

            return packet_data;
        }

        usleep(5000);
    }
}

struct SwiftNetServerPacketData* swiftnet_server_make_request(struct SwiftNetServer* const server, struct SwiftNetPacketBuffer* const packet, const struct SwiftNetClientAddrData addr_data, const uint32_t timeout_ms) {
    struct RequestSent* const request_sent = construct_request_sent(addr_data.sender_address);

    const uint32_t packet_length = packet->packet_append_pointer - packet->packet_data_start;

    const struct SwiftNetPortInfo port_info = {
        .destination_port = addr_data.port,
        .source_port = server->server_port
    };

    swiftnet_send_packet(server, addr_data.maximum_transmission_unit, port_info, packet, packet_length, &addr_data.sender_address, &server->packets_sending, &server->packets_sending_memory_allocator, server->pcap, server->eth_header, server->loopback, server->addr_type, server->prepend_size, request_sent, false, 0);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t start = (uint32_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

    while (1) {
        gettimeofday(&tv, NULL);
        uint32_t end = (uint32_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

        if (start + timeout_ms < end) {
            delete_request_sent(request_sent);

            return NULL;
        }

        if (request_sent->packet_data != NULL) {
            struct SwiftNetServerPacketData* const packet_data = request_sent->packet_data;

            allocator_free(&requests_sent_memory_allocator, (void*)request_sent);

            return packet_data;
        }

        usleep(5000);
    }
}

#endif
