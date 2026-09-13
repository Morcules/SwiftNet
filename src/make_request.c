#include "internal/internal.h"
#include "swift_net.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#ifndef SWIFT_NET_DISABLE_REQUESTS

static inline void delete_request_sent(struct RequestSent* restrict const request_sent) {
    LOCK_ATOMIC_DATA_TYPE(&requests_sent.atomic_lock)

    hashmap_remove(&request_sent->packet_id, sizeof(uint16_t), &requests_sent);

    UNLOCK_ATOMIC_DATA_TYPE(&requests_sent.atomic_lock)

    allocator_free(&requests_sent_memory_allocator, request_sent);
}

static inline struct RequestSent* construct_request_sent(const struct in_addr address) {
    struct RequestSent* const request_sent = allocator_allocate(&requests_sent_memory_allocator);

    *request_sent = (struct RequestSent){.address = address, .packet_data = NULL};

    return request_sent;
}

struct SwiftNetClientPacketData* swiftnet_client_make_request(struct SwiftNetClientConnection* const client, struct SwiftNetPacketBuffer* const packet, const uint32_t timeout_ms, const uint32_t bytes_to_send) {
    struct RequestSent* request_sent;
    struct timeval tv;
    uint32_t start;
    uint32_t end;

    request_sent = construct_request_sent(client->server_addr);

    swiftnet_send_packet(client->maximum_transmission_unit, client->port_info, packet, bytes_to_send, &client->server_addr, &client->packets_sending, &client->packets_sending_memory_allocator, client->eth_header, client->network_data, request_sent, false, 0);


    gettimeofday(&tv, NULL);
    start = (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);

    goto check_response;


check_response:
    gettimeofday(&tv, NULL);
    end = (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);

    if (start + timeout_ms < end) {
        delete_request_sent(request_sent);

        return NULL;
    }

    if (atomic_load_explicit(&request_sent->packet_data, memory_order_acquire) != NULL) {
        struct SwiftNetClientPacketData* const packet_data = request_sent->packet_data;

        allocator_free(&requests_sent_memory_allocator, request_sent);

        return packet_data;
    }

    usleep(10);

    goto check_response;
}

struct SwiftNetServerPacketData* swiftnet_server_make_request(struct SwiftNetServer* const server, struct SwiftNetPacketBuffer* const packet, const struct SwiftNetClientAddrData addr_data, const uint32_t timeout_ms, const uint32_t bytes_to_send) {
    struct RequestSent* request_sent;
    struct SwiftNetPortInfo port_info;
    struct timeval tv;
    uint32_t start;
    uint32_t end;

    request_sent = construct_request_sent(addr_data.sender_address);

    port_info = (struct SwiftNetPortInfo){.destination_port = addr_data.port, .source_port = server->server_port};

    swiftnet_send_packet(addr_data.maximum_transmission_unit, port_info, packet, bytes_to_send, &addr_data.sender_address, &server->packets_sending, &server->packets_sending_memory_allocator, server->eth_header, server->network_data, request_sent, false, 0);

    gettimeofday(&tv, NULL);
    start = (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);

    goto check_response;


check_response:
    gettimeofday(&tv, NULL);
    end = (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);

    if (start + timeout_ms < end) {
        delete_request_sent(request_sent);

        return NULL;
    }

    if (atomic_load_explicit(&request_sent->packet_data, memory_order_acquire) != NULL) {
        struct SwiftNetServerPacketData* const packet_data = request_sent->packet_data;

        allocator_free(&requests_sent_memory_allocator, request_sent);

        return packet_data;
    }

    usleep(5000);

    goto check_response;
}

#endif
