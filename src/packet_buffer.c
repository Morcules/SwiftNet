#include "internal/internal.h"
#include "swift_net.h"

static inline struct SwiftNetPacketBuffer create_packet_buffer(const uint32_t buffer_size) {
    uint8_t* const mem = malloc(buffer_size + PACKET_HEADER_SIZE + sizeof(struct ether_header));

    uint8_t* const data_pointer = mem + PACKET_HEADER_SIZE + sizeof(struct ether_header);

    return (struct SwiftNetPacketBuffer){
        .packet_buffer_start = mem,
        .packet_data_start = data_pointer,
        .packet_append_pointer = data_pointer 
    };
}

struct SwiftNetPacketBuffer swiftnet_server_create_packet_buffer(const uint32_t buffer_size) {
    return create_packet_buffer(buffer_size);
}

struct SwiftNetPacketBuffer swiftnet_client_create_packet_buffer(const uint32_t buffer_size) {
    return create_packet_buffer(buffer_size);
}

void swiftnet_server_destroy_packet_buffer(const struct SwiftNetPacketBuffer* const packet) {
    free(packet->packet_buffer_start);
}

void swiftnet_client_destroy_packet_buffer(const struct SwiftNetPacketBuffer* const packet) {
    free(packet->packet_buffer_start);
}
