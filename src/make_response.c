#include "internal/internal.h"
#include "swift_net.h"

#ifdef SWIFT_NET_REQUESTS

void swiftnet_client_make_response(struct SwiftNetClientConnection* const client, struct SwiftNetClientPacketData* const packet_data, struct SwiftNetPacketBuffer* const buffer) {
    const uint32_t packet_length = buffer->packet_append_pointer - buffer->packet_data_start;

    swiftnet_send_packet(client, client->maximum_transmission_unit, client->port_info, buffer, packet_length, &client->server_addr, &client->packets_sending, &client->packets_sending_memory_allocator, client->pcap, client->eth_header, client->loopback, client->addr_type, client->prepend_size, NULL, true, packet_data->metadata.packet_id);
}

void swiftnet_server_make_response(struct SwiftNetServer* const server, struct SwiftNetServerPacketData* const packet_data, struct SwiftNetPacketBuffer* const buffer) {
    const uint32_t packet_length = buffer->packet_append_pointer - buffer->packet_data_start;

    const struct SwiftNetPortInfo port_info = {
        .source_port = server->server_port,
        .destination_port = packet_data->metadata.port_info.source_port
    };

    swiftnet_send_packet(server, packet_data->metadata.sender.maximum_transmission_unit, port_info, buffer, packet_length, &packet_data->metadata.sender.sender_address, &server->packets_sending, &server->packets_sending_memory_allocator, server->pcap, server->eth_header, server->loopback, server->addr_type, server->prepend_size, NULL, true, packet_data->metadata.packet_id);
}

#endif
