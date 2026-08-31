#include "../internal.h"
#include "../../swift_net.h"
#include <net/ethernet.h>
#include <stdint.h>
#include <stdlib.h>

static inline struct SwiftNetPacketBuffer create_packet_buffer(const uint32_t buffer_size) {
    uint8_t* restrict const mem = malloc(buffer_size + PACKET_HEADER_SIZE + sizeof(struct ether_header) + sizeof(struct SwiftNetPacketMetadata));
    uint8_t* restrict const data_pointer = mem + PACKET_HEADER_SIZE + sizeof(struct ether_header) + sizeof(struct SwiftNetPacketMetadata);

    return (struct SwiftNetPacketBuffer){
        .packet_buffer_start = mem,
        .packet_data_start = data_pointer,
        .packet_append_pointer = data_pointer 
    };
}

struct SwiftNetPacketBuffer swiftnet_client_create_packet_buffer(const uint32_t buffer_size, MAYBE_UNUSED const struct SwiftNetClientConnection* const client_connection) {
    return create_packet_buffer(buffer_size);
}

struct SwiftNetPacketBuffer swiftnet_server_create_packet_buffer(const uint32_t buffer_size, MAYBE_UNUSED const struct SwiftNetServer* const server) {
    return create_packet_buffer(buffer_size);
}

static inline void resize_packet_buffer(uint32_t new_buffer_size, struct SwiftNetPacketBuffer* restrict const packet_buffer) {
    uint8_t* new_ptr;
    uint8_t* data_start; 

    const uint32_t current_offset = (uint32_t)(packet_buffer->packet_append_pointer - packet_buffer->packet_data_start);


    new_buffer_size += PACKET_HEADER_SIZE + sizeof(struct ether_header) + sizeof(struct SwiftNetPacketMetadata);

    new_ptr = realloc(packet_buffer->packet_buffer_start, new_buffer_size);
    if (unlikely(new_ptr == NULL)) {
        PRINT_ERROR("Failed to realloc");
        exit(EXIT_FAILURE);
    }

    data_start = new_ptr + PACKET_HEADER_SIZE + sizeof(struct ether_header);

    *packet_buffer = (struct SwiftNetPacketBuffer){
        .packet_buffer_start = new_ptr,
        .packet_data_start = data_start,
        .packet_append_pointer = data_start + current_offset
    };
}

void swiftnet_client_resize_packet_buffer(uint32_t new_buffer_size, struct SwiftNetPacketBuffer* restrict const packet_buffer, MAYBE_UNUSED const struct SwiftNetClientConnection* const client_connection) {
    resize_packet_buffer(new_buffer_size, packet_buffer);
}

void swiftnet_server_resize_packet_buffer(uint32_t new_buffer_size, struct SwiftNetPacketBuffer* restrict const packet_buffer, MAYBE_UNUSED const struct SwiftNetServer* const server) {
    resize_packet_buffer(new_buffer_size, packet_buffer);
}

static inline void write_packet_buffer(const uint32_t byte_offset, struct SwiftNetPacketBuffer* restrict const packet_buffer, const void* restrict const data, const uint32_t data_size) {
    memcpy(packet_buffer->packet_data_start + byte_offset, data, data_size);
}

void swiftnet_client_write_packet_buffer(const uint32_t byte_offset, struct SwiftNetPacketBuffer* restrict const packet_buffer, void* restrict const data, const uint32_t data_size, MAYBE_UNUSED const struct SwiftNetClientConnection* const client_connection) {
    write_packet_buffer(byte_offset, packet_buffer, data, data_size);
}

void swiftnet_server_write_packet_buffer(const uint32_t byte_offset, struct SwiftNetPacketBuffer* restrict const packet_buffer, void* restrict const data, const uint32_t data_size, MAYBE_UNUSED const struct SwiftNetServer* const server) {
    write_packet_buffer(byte_offset, packet_buffer, data, data_size);
}

// These functions append data to a packet buffer and advance the current pointer by the data size.
static inline void validate_append_to_packet_args(const void* restrict const data, const uint32_t data_size) {
    if(unlikely(data == NULL || data_size == 0)) {
        PRINT_ERROR("Error: Invalid arguments given");
        exit(EXIT_FAILURE);
    }
}

static inline void append_data(uint8_t* restrict * restrict const append_pointer, const void* restrict const data, const uint32_t data_size) {
    memcpy(*append_pointer, data, data_size);

    (*append_pointer) += data_size;
}

void swiftnet_append_to_buffer(const void* restrict const data, const uint32_t data_size, struct SwiftNetPacketBuffer* restrict const buffer) {
    #ifndef SWIFT_NET_DISABLE_ERROR_CHECKING
        validate_append_to_packet_args(data, data_size);
    #endif

    append_data(&buffer->packet_append_pointer, data, data_size);
}

static inline void destroy_packet_buffer(const struct SwiftNetPacketBuffer* restrict const packet) {
    free(packet->packet_buffer_start);
}

void swiftnet_client_destroy_packet_buffer(const struct SwiftNetPacketBuffer* restrict const packet, MAYBE_UNUSED const struct SwiftNetClientConnection* const client_connection) {
    destroy_packet_buffer(packet);
}

void swiftnet_server_destroy_packet_buffer(const struct SwiftNetPacketBuffer* restrict const packet, MAYBE_UNUSED const struct SwiftNetServer* const server) {
    destroy_packet_buffer(packet);
}
