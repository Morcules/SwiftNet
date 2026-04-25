#include "internal/internal.h"
#include "swift_net.h"
#include <net/ethernet.h>
#include <stdint.h>
#include <stdlib.h>

static inline struct SwiftNetPacketBuffer create_packet_buffer(const uint32_t buffer_size) {
    uint8_t* const mem = malloc(buffer_size + PACKET_HEADER_SIZE + sizeof(struct ether_header));

    uint8_t* const data_pointer = mem + PACKET_HEADER_SIZE + sizeof(struct ether_header);

    return (struct SwiftNetPacketBuffer){
        .packet_buffer_start = mem,
        .packet_data_start = data_pointer,
        .packet_append_pointer = data_pointer 
    };
}

struct SwiftNetPacketBuffer swiftnet_create_packet_buffer(const uint32_t buffer_size) {
    return create_packet_buffer(buffer_size);
}

void swiftnet_resize_packet_buffer(uint32_t new_buffer_size, struct SwiftNetPacketBuffer* const packet_buffer) {
    const uint32_t current_offset = packet_buffer->packet_append_pointer - packet_buffer->packet_data_start;

    new_buffer_size += PACKET_HEADER_SIZE + sizeof(struct ether_header);

    void* const new_ptr = realloc(packet_buffer->packet_buffer_start, new_buffer_size);

    if (unlikely(new_ptr == NULL)) {
        PRINT_ERROR("Failed to realloc");
        exit(EXIT_FAILURE);
    }

    void* const data_start = new_ptr + PACKET_HEADER_SIZE + sizeof(struct ether_header);

    packet_buffer->packet_buffer_start = new_ptr;
    packet_buffer->packet_data_start = data_start;
    packet_buffer->packet_append_pointer = data_start + current_offset;
}

void swiftnet_write_packet_buffer(const uint32_t byte_offset, struct SwiftNetPacketBuffer* const packet_buffer, void* const data, const uint32_t data_size) {
    memcpy(packet_buffer->packet_data_start + byte_offset, data, data_size);
}

void swiftnet_destroy_packet_buffer(const struct SwiftNetPacketBuffer* const packet) {
    free(packet->packet_buffer_start);
}
