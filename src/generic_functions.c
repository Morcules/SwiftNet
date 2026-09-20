#include "internal/internal.h"
#include "internal/networking.h"
#include "swift_net.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Set the handler for incoming packets/messages on the server or client
static inline void swiftnet_validate_new_handler(void(*new_handler)(void)) {
    #ifndef SWIFT_NET_DISABLE_ERROR_CHECKING
        if(unlikely(new_handler == NULL)) {
            PRINT_ERROR("Error: Invalid arguments given");
            exit(EXIT_FAILURE);
        }
    #endif
}

void swiftnet_client_set_message_handler(struct SwiftNetClientConnection* const client, void (*new_handler)(struct SwiftNetClientPacketData* const, void* const), void* const user_arg) {
    swiftnet_validate_new_handler((void(*)(void))new_handler);

    atomic_store_explicit(&client->packet_handler, new_handler, memory_order_release);
    atomic_store_explicit(&client->packet_handler_user_arg, user_arg, memory_order_release);
}

void swiftnet_server_set_message_handler(struct SwiftNetServer* const server, void (* const new_handler)(struct SwiftNetServerPacketData* const, void* const), void* const user_arg) {
    swiftnet_validate_new_handler((void(*)(void))new_handler);

    atomic_store_explicit(&server->packet_handler, new_handler, memory_order_release);
    atomic_store_explicit(&server->packet_handler_user_arg, user_arg, memory_order_release);
}

// Read packet data into buffers
void* swiftnet_client_read_packet(struct SwiftNetClientPacketData* restrict const packet_data, const uint32_t data_size) {
    const uint32_t data_already_read = (uint32_t)(packet_data->current_pointer - packet_data->data) + data_size;
    if (data_already_read > packet_data->metadata.data_length) {
        PRINT_ERROR("Error: Tried to read more data than there actually is");
        return NULL;
    }

    void* restrict const ptr = packet_data->current_pointer;

    packet_data->current_pointer += data_size;

    return ptr;
}

void* swiftnet_server_read_packet(struct SwiftNetServerPacketData* restrict const packet_data, const uint32_t data_size) {
    const uint32_t data_already_read = (uint32_t)(packet_data->current_pointer - packet_data->data) + data_size;
    if (data_already_read > packet_data->metadata.data_length) {
        PRINT_ERROR("Error: Tried to read more data than there actually is");
        return NULL;
    }

    void* restrict const ptr = packet_data->current_pointer;

    packet_data->current_pointer += data_size;

    return ptr;
}

void swiftnet_client_destroy_packet_data(struct SwiftNetClientPacketData* restrict const packet_data, MAYBE_UNUSED struct SwiftNetClientConnection* const client_conn) {
    if(packet_data->internal_pending_message != NULL) {
        free(packet_data->internal_pending_message->chunks_received);
        
        allocator_free(&pending_message_memory_allocator, packet_data->internal_pending_message);

        free(packet_data->data);

        allocator_free(&client_packet_data_memory_allocator, packet_data);
    } else {
        allocator_free(&packet_buffer_memory_allocator, packet_data->buffer_start);
        allocator_free(&client_packet_data_memory_allocator, packet_data);
    }
}

void swiftnet_server_destroy_packet_data(struct SwiftNetServerPacketData* restrict const packet_data, MAYBE_UNUSED struct SwiftNetServer* const server) {
    if(packet_data->internal_pending_message != NULL) {
        free(packet_data->internal_pending_message->chunks_received);

        allocator_free(&pending_message_memory_allocator, packet_data->internal_pending_message);

        free(packet_data->data);

        allocator_free(&server_packet_data_memory_allocator, packet_data);
    } else {
        allocator_free(&packet_buffer_memory_allocator, packet_data->buffer_start);
        allocator_free(&server_packet_data_memory_allocator, packet_data);
    }
}
