#include "internal/internal.h"
#include "swift_net.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// These functions append data to a packet buffer and advance the current pointer by the data size.

static inline void validate_append_to_packet_args(const void* const data, const uint32_t data_size) {
    if(unlikely(data == NULL || data_size == 0)) {
        PRINT_ERROR("Error: Invalid arguments given");
        exit(EXIT_FAILURE);
    }
}

static inline void append_data(uint8_t** const append_pointer, const void* const data, const uint32_t data_size) {
    memcpy(*append_pointer, data, data_size);

    (*append_pointer) += data_size;
}

void swiftnet_client_append_to_packet(const void* const data, const uint32_t data_size, struct SwiftNetPacketBuffer* const packet) {
    #ifdef SWIFT_NET_ERROR
        validate_append_to_packet_args(data, data_size);
    #endif

    append_data(&packet->packet_append_pointer, data, data_size);
}

void swiftnet_server_append_to_packet(const void* const data, const uint32_t data_size, struct SwiftNetPacketBuffer* const packet) {
    #ifdef SWIFT_NET_ERROR
        validate_append_to_packet_args(data, data_size);
    #endif

    append_data(&packet->packet_append_pointer, data, data_size);
}

// Set the handler for incoming packets/messages on the server or client
//
static inline void swiftnet_validate_new_handler(const void* const new_handler) {
    #ifdef SWIFT_NET_ERROR
        if(unlikely(new_handler == NULL)) {
            PRINT_ERROR("Error: Invalid arguments given");
            exit(EXIT_FAILURE);
        }
    #endif
}

void swiftnet_client_set_message_handler(struct SwiftNetClientConnection* const client, void (* const new_handler)(struct SwiftNetClientPacketData* const, void* const), void* const user_arg) {
    swiftnet_validate_new_handler(new_handler);

    atomic_store_explicit(&client->packet_handler, new_handler, memory_order_release);
    atomic_store_explicit(&client->packet_handler_user_arg, user_arg, memory_order_release);
}

void swiftnet_server_set_message_handler(struct SwiftNetServer* const server, void (* const new_handler)(struct SwiftNetServerPacketData* const, void* const), void* const user_arg) {
    swiftnet_validate_new_handler(new_handler);

    atomic_store_explicit(&server->packet_handler, new_handler, memory_order_release);
    atomic_store_explicit(&server->packet_handler_user_arg, user_arg, memory_order_release);
}

// Read packet data into buffers

void* swiftnet_client_read_packet(struct SwiftNetClientPacketData* const packet_data, const uint32_t data_size) {
    const uint32_t data_already_read = (packet_data->current_pointer - packet_data->data) + data_size;
    if (data_already_read > packet_data->metadata.data_length) {
        PRINT_ERROR("Error: Tried to read more data than there actually is");
        return NULL;
    }

    void* const ptr = packet_data->current_pointer;

    packet_data->current_pointer += data_size;

    return ptr;
}

void* swiftnet_server_read_packet(struct SwiftNetServerPacketData* const packet_data, const uint32_t data_size) {
    const uint32_t data_already_read = (packet_data->current_pointer - packet_data->data) + data_size;
    if (data_already_read > packet_data->metadata.data_length) {
        PRINT_ERROR("Error: Tried to read more data than there actually is");
        return NULL;
    }

    void* const ptr = packet_data->current_pointer;

    packet_data->current_pointer += data_size;

    return ptr;
}

void swiftnet_client_destroy_packet_data(struct SwiftNetClientPacketData* const packet_data, struct SwiftNetClientConnection* const client_conn) {
    if(packet_data->internal_pending_message != NULL) {
        free(packet_data->internal_pending_message->chunks_received);
        
        allocator_free(&client_conn->pending_messages_memory_allocator, packet_data->internal_pending_message);

        free(packet_data->data);
    } else {
        allocator_free(&packet_buffer_memory_allocator, packet_data->data - PACKET_HEADER_SIZE - client_conn->prepend_size);
        allocator_free(&client_packet_data_memory_allocator, packet_data);
    }
}

void swiftnet_server_destroy_packet_data(struct SwiftNetServerPacketData* const packet_data, struct SwiftNetServer* const server) {
    if(packet_data->internal_pending_message != NULL) {
        free(packet_data->internal_pending_message->chunks_received);

        allocator_free(&server->pending_messages_memory_allocator, packet_data->internal_pending_message);

        free(packet_data->data);
    } else {
        allocator_free(&packet_buffer_memory_allocator, packet_data->data - PACKET_HEADER_SIZE - server->prepend_size);
        allocator_free(&server_packet_data_memory_allocator, packet_data);
    }
}
