#include "internal/networking.h"
#include "swift_net.h"
#include <netdb.h>
#include <pcap/dlt.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <net/ethernet.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "internal/internal.h"
#include <netinet/in.h>

static inline enum RequestLostPacketsReturnType request_lost_packets_bitarray(const uint8_t* restrict const raw_data, const uint32_t data_size, const struct SwiftNetNetworkData* restrict const network_data, struct SwiftNetPacketSending* const packet_sending) {
    uint8_t times_checked;
    enum PacketSendingUpdated status;
    

    goto request_lost_packets;

request_lost_packets:
    if(check_debug_flag(SWIFTNET_DEBUG_LOST_PACKETS)) {
        send_debug_message("Requested list of lost packets: {\"packet_id\": %d}\n", htons(packet_sending->packet_id));
    }

    SWIFTNET_SEND_PACKET(network_data, raw_data, data_size);

    for(times_checked = 0; times_checked < 0xFF; times_checked++) {
        status = atomic_load_explicit(&packet_sending->updated, memory_order_acquire);

        switch (status) {
            case NO_UPDATE:
                break;
            case UPDATED_LOST_CHUNKS:
                atomic_store_explicit(&packet_sending->updated, NO_UPDATE, memory_order_release);
                return REQUEST_LOST_PACKETS_RETURN_UPDATED_BIT_ARRAY;
            case SUCCESSFULLY_RECEIVED:
                atomic_store_explicit(&packet_sending->updated, NO_UPDATE, memory_order_release);

                return REQUEST_LOST_PACKETS_RETURN_COMPLETED_PACKET;
        }

        usleep(1000);
    }

    goto request_lost_packets;
}

static inline void handle_lost_packets(
    struct SwiftNetPacketSending* const packet_sending,
    const uint32_t mtu,
    const struct SwiftNetPacketBuffer* restrict const packet, 
    const struct ether_header eth_hdr,
    const struct in_addr* restrict const destination_address,
    const uint16_t source_port,
    const uint16_t destination_port,
    struct SwiftNetMemoryAllocator* const packets_sending_memory_allocator,
    struct SwiftNetHashMap* const packets_sending,
    const bool loopback,
    const struct SwiftNetNetworkData* restrict const network_data
    #ifdef SWIFT_NET_REQUESTS
        , const bool response
        , const uint8_t packet_type
    #endif
) {
    uint8_t prepend_size = GET_PREPEND_SIZE(network_data);
    struct SwiftNetPortInfo port_info;
    struct ip request_lost_packets_ip_header;
    struct SwiftNetPacketInfo request_lost_packets_bit_array;
    uint32_t packet_length;
    uint32_t chunk_amount;
    struct SwiftNetPacketInfo resend_chunk_packet_info;
    struct ip resend_chunk_ip_header;
    uint8_t temp_data_buffer[prepend_size + PACKET_HEADER_SIZE];
    enum RequestLostPacketsReturnType request_lost_packets_bitarray_response;


    port_info = (struct SwiftNetPortInfo){
        .source_port = source_port,
        .destination_port = destination_port
    };

    request_lost_packets_ip_header = construct_ip_header(*destination_address, PACKET_HEADER_SIZE, packet_sending->packet_id);

    request_lost_packets_bit_array = construct_packet_info(
        0x00,
        SEND_LOST_PACKETS_REQUEST,
        1,
        0,
        port_info
    );

    HANDLE_PACKET_CONSTRUCTION(&request_lost_packets_ip_header, &request_lost_packets_bit_array, network_data, &eth_hdr, PACKET_HEADER_SIZE + prepend_size, request_lost_packets_buffer);
 
    HANDLE_CHECKSUM(request_lost_packets_buffer, sizeof(request_lost_packets_buffer), network_data);
 
    packet_length = packet->packet_append_pointer - packet->packet_data_start;
    chunk_amount = (packet_length + (mtu - PACKET_HEADER_SIZE) - 1) / (mtu - PACKET_HEADER_SIZE);

    resend_chunk_packet_info = construct_packet_info(
        packet_length,
        #ifdef SWIFT_NET_REQUESTS
        packet_type,
        #else
        MESSAGE,
        #endif
        chunk_amount,
        0,
        port_info
    );
 
    resend_chunk_ip_header = construct_ip_header(*destination_address, mtu, packet_sending->packet_id);

    HANDLE_PACKET_CONSTRUCTION(&resend_chunk_ip_header, &resend_chunk_packet_info, network_data, &eth_hdr, prepend_size + PACKET_HEADER_SIZE, prepend_buffer);

    while(1) {
        uint32_t i;
        uint32_t lost_chunk_index;
        uint32_t current_offset;
        uint8_t* restrict current_buffer_header_ptr;


        request_lost_packets_bitarray_response = request_lost_packets_bitarray(request_lost_packets_buffer, PACKET_HEADER_SIZE + prepend_size, network_data, packet_sending);

        LOCK_ATOMIC_DATA_TYPE(&packets_sending->atomic_lock);

        switch (request_lost_packets_bitarray_response) {
            case REQUEST_LOST_PACKETS_RETURN_UPDATED_BIT_ARRAY:
                break;
            case REQUEST_LOST_PACKETS_RETURN_COMPLETED_PACKET:
                free((void*)packet_sending->lost_chunks);

                hashmap_remove(&packet_sending->packet_id, sizeof(packet_sending->packet_id), packets_sending);

                UNLOCK_ATOMIC_DATA_TYPE(&packets_sending->atomic_lock);

                allocator_free(packets_sending_memory_allocator, packet_sending);

                return;
        }
    
        for(i = 0; i < packet_sending->lost_chunks_size; i++) {
            lost_chunk_index = packet_sending->lost_chunks[i];

            current_offset = lost_chunk_index * (mtu - PACKET_HEADER_SIZE);

            current_buffer_header_ptr = packet->packet_data_start + current_offset - prepend_size - PACKET_HEADER_SIZE;

            memcpy(temp_data_buffer, current_buffer_header_ptr, prepend_size + PACKET_HEADER_SIZE);

            memcpy(current_buffer_header_ptr, prepend_buffer, prepend_size + PACKET_HEADER_SIZE);

            if (check_debug_flag(SWIFTNET_DEBUG_LOST_PACKETS) == true) {
                send_debug_message("Packet lost: {\"packet_id\": %d, \"chunk index\": %d}\n", packet_sending->packet_id, lost_chunk_index);
            }
    
            memcpy(current_buffer_header_ptr + sizeof(struct ip) + prepend_size + offsetof(struct SwiftNetPacketInfo, chunk_index), &lost_chunk_index, SIZEOF_FIELD(struct SwiftNetPacketInfo, chunk_index));
    
            memset(current_buffer_header_ptr + prepend_size + sizeof(struct ip) + offsetof(struct SwiftNetPacketInfo, checksum), 0x00, SIZEOF_FIELD(struct SwiftNetPacketInfo, checksum));

            if(current_offset + mtu - PACKET_HEADER_SIZE >= packet_length) {
                uint32_t bytes_to_complete;
                uint16_t new_ip_len;


                bytes_to_complete = packet_length - current_offset;

                new_ip_len = htons(bytes_to_complete + PACKET_HEADER_SIZE);
                memcpy(current_buffer_header_ptr + offsetof(struct ip, ip_len), &new_ip_len, SIZEOF_FIELD(struct ip, ip_len));
                
                HANDLE_CHECKSUM(current_buffer_header_ptr, prepend_size + PACKET_HEADER_SIZE + bytes_to_complete, network_data);
    
                SWIFTNET_SEND_PACKET(network_data, current_buffer_header_ptr, bytes_to_complete + PACKET_HEADER_SIZE + prepend_size);
            } else {
                HANDLE_CHECKSUM(current_buffer_header_ptr, mtu + prepend_size, network_data);

                SWIFTNET_SEND_PACKET(network_data, current_buffer_header_ptr, mtu + prepend_size);
            }

            memcpy(current_buffer_header_ptr, temp_data_buffer, prepend_size + PACKET_HEADER_SIZE);
        }

        UNLOCK_ATOMIC_DATA_TYPE(&packets_sending->atomic_lock);
    }
}

inline void swiftnet_send_packet(
    const void* const connection,
    const uint32_t target_maximum_transmission_unit,
    const struct SwiftNetPortInfo port_info,
    const struct SwiftNetPacketBuffer* const packet,
    const uint32_t packet_length,
    const struct in_addr* const target_addr,
    struct SwiftNetHashMap* const packets_sending,
    struct SwiftNetMemoryAllocator* const packets_sending_memory_allocator,
    const struct ether_header eth_hdr,
    const bool loopback,
    const struct SwiftNetNetworkData network_data
    #ifdef SWIFT_NET_REQUESTS
        , struct RequestSent* const request_sent
        , const bool response
        , const uint16_t request_packet_id
    #endif
) {
    uint32_t mtu;
    uint32_t chunk_amount;
    uint16_t packet_id;
    #ifdef SWIFT_NET_REQUESTS
    uint8_t packet_type;
    #endif


    mtu = MIN(target_maximum_transmission_unit, maximum_transmission_unit);

    #ifdef SWIFT_NET_DEBUG
        if (check_debug_flag(SWIFTNET_DEBUG_PACKETS_SENDING)) {
            send_debug_message("Sending packet: {\"destination_ip_address\": \"%s\", \"destination_port\": %d, \"packet_length\": %d}\n", inet_ntoa(*target_addr), port_info.destination_port, packet_length);
        }
    #endif

    #ifdef SWIFT_NET_REQUESTS
        if (response == true) {
            packet_id = request_packet_id;
        } else {
            packet_id = rand();
        }

        if (request_sent != NULL) {
            uint16_t* hashmap_key_mem;


            request_sent->packet_id = packet_id;

            LOCK_ATOMIC_DATA_TYPE(&requests_sent.atomic_lock);

            hashmap_key_mem = allocator_allocate(&uint16_memory_allocator);
            *hashmap_key_mem = packet_id;

            hashmap_insert(hashmap_key_mem, sizeof(uint16_t), request_sent, &requests_sent);

            UNLOCK_ATOMIC_DATA_TYPE(&requests_sent.atomic_lock);
        }
    #else
        packet_id = rand();
    #endif

    #ifdef SWIFT_NET_REQUESTS
    packet_type = response ? RESPONSE : request_sent == NULL ? MESSAGE : REQUEST;
    #endif

    chunk_amount = (packet_length + (mtu - PACKET_HEADER_SIZE) - 1) / (mtu - PACKET_HEADER_SIZE);

    const uint8_t prepend_size = GET_PREPEND_SIZE(&network_data);

    if(packet_length > mtu) {
        struct SwiftNetPacketInfo packet_info;
        struct ip ip_header;
        uint16_t net_order_len;
        struct SwiftNetPacketSending* new_packet_sending;
        uint16_t* key_data_mem;
        uint8_t temp_data_buffer[prepend_size + PACKET_HEADER_SIZE];
        uint32_t i;
        uint32_t current_offset;
        uint8_t* buffer_header_location;
        uint16_t bytes_to_send;
        uint16_t bytes_to_send_net_order;


        packet_info = construct_packet_info(
            packet_length,
            #ifdef SWIFT_NET_REQUESTS
            packet_type,
            #else
            MESSAGE,
            #endif
            chunk_amount,
            0,
            port_info
        );

        ip_header = construct_ip_header(*target_addr, mtu, packet_id);

        net_order_len = htons(mtu + prepend_size);
        ip_header.ip_len = net_order_len;

        new_packet_sending = allocator_allocate(packets_sending_memory_allocator);
        if(unlikely(new_packet_sending == NULL)) {
            PRINT_ERROR("Failed to send a packet: exceeded maximum amount of sending packets at the same time");
            return;
        }

        LOCK_ATOMIC_DATA_TYPE(&packets_sending->atomic_lock);

        key_data_mem = allocator_allocate(&uint16_memory_allocator);
        *key_data_mem = packet_id;

        *new_packet_sending = (struct SwiftNetPacketSending){
            .locked = false,
            .lost_chunks = NULL,
            .lost_chunks_size = 0,
            .packet_id = packet_id,
        };

        #ifndef DISABLE_DYNAMIC_RATE_LIMITING
        atomic_store_explicit(&new_packet_sending->current_send_delay, 50, memory_order_release);
        #endif
        atomic_store_explicit(&new_packet_sending->updated, NO_UPDATE, memory_order_release);

        hashmap_insert(key_data_mem, sizeof(uint16_t), new_packet_sending, packets_sending);

        UNLOCK_ATOMIC_DATA_TYPE(&packets_sending->atomic_lock);

        HANDLE_PACKET_CONSTRUCTION(&ip_header, &packet_info, &network_data, &eth_hdr, prepend_size + PACKET_HEADER_SIZE, prepend_buffer);
        
        for(i = 0; ; i++) {
            current_offset = i * (mtu - PACKET_HEADER_SIZE);

            #ifdef SWIFT_NET_DEBUG
                if (check_debug_flag(SWIFTNET_DEBUG_PACKETS_SENDING)) {
                    send_debug_message("Sent chunk: {\"chunk_index\": %d}\n", i);
                }
            #endif

            buffer_header_location = packet->packet_data_start + current_offset - prepend_size - PACKET_HEADER_SIZE;

            memcpy(temp_data_buffer, buffer_header_location, prepend_size + PACKET_HEADER_SIZE);

            memcpy(buffer_header_location, prepend_buffer, prepend_size + PACKET_HEADER_SIZE);

            memcpy(buffer_header_location + sizeof(struct ip) + prepend_size + offsetof(struct SwiftNetPacketInfo, chunk_index), &i, SIZEOF_FIELD(struct SwiftNetPacketInfo, chunk_index));
            
            memset(buffer_header_location + sizeof(struct ip) + prepend_size + offsetof(struct SwiftNetPacketInfo, checksum), 0x00, SIZEOF_FIELD(struct SwiftNetPacketInfo, checksum));
            
            if(current_offset + (mtu - PACKET_HEADER_SIZE) >= packet_info.packet_length) {
                bytes_to_send = (uint16_t)(packet_length - current_offset + PACKET_HEADER_SIZE + prepend_size);

                bytes_to_send_net_order = htons(bytes_to_send - prepend_size);

                memcpy(buffer_header_location + prepend_size + offsetof(struct ip, ip_len), &bytes_to_send_net_order, SIZEOF_FIELD(struct ip, ip_len));

                HANDLE_CHECKSUM(buffer_header_location, bytes_to_send, &network_data);

                SWIFTNET_SEND_PACKET(&network_data, buffer_header_location, bytes_to_send);

                memcpy(buffer_header_location, temp_data_buffer, prepend_size + PACKET_HEADER_SIZE);

                handle_lost_packets(new_packet_sending, mtu, packet, eth_hdr, target_addr, port_info.source_port, port_info.destination_port, packets_sending_memory_allocator, packets_sending, loopback, &network_data
                #ifdef SWIFT_NET_REQUESTS
                    , response
                    , packet_type
                #endif
                );
                
                break;
            } else {
                bytes_to_send = prepend_size + mtu;
                
                HANDLE_CHECKSUM(buffer_header_location, bytes_to_send, &network_data);

                SWIFTNET_SEND_PACKET(&network_data, buffer_header_location, bytes_to_send);

                memcpy(buffer_header_location, temp_data_buffer, prepend_size + PACKET_HEADER_SIZE);

                #ifndef DISABLE_DYNAMIC_RATE_LIMITING
                usleep(atomic_load_explicit(&new_packet_sending->current_send_delay, memory_order_acquire));
                #endif
            }
        }
    } else {
        uint32_t final_packet_size;
        struct SwiftNetPacketInfo packet_info;
        struct ip ip_header;


        final_packet_size = prepend_size + PACKET_HEADER_SIZE + packet_length;

        packet_info = construct_packet_info(
            packet_length,
            #ifdef SWIFT_NET_REQUESTS
            packet_type,
            #else
            MESSAGE,
            #endif
            1,
            0,
            port_info
        );

        ip_header = construct_ip_header(*target_addr, final_packet_size - prepend_size, packet_id);

        if(GET_ADDR_TYPE(&network_data) == DLT_NULL) {
            uint32_t family = PF_INET;

            memcpy(packet->packet_buffer_start + sizeof(struct ether_header) - sizeof(family), &family, sizeof(family));
            memcpy(packet->packet_buffer_start + sizeof(struct ether_header), &ip_header, sizeof(ip_header));
            memcpy(packet->packet_buffer_start + sizeof(struct ether_header) + sizeof(struct ip), &packet_info, sizeof(packet_info));

            memcpy(packet->packet_buffer_start + PACKET_HEADER_SIZE + sizeof(struct ether_header), packet->packet_data_start, packet_length);

            HANDLE_CHECKSUM(packet->packet_buffer_start + sizeof(struct ether_header) - sizeof(family), final_packet_size, &network_data);

            SWIFTNET_SEND_PACKET(&network_data, packet->packet_buffer_start + sizeof(struct ether_header) - sizeof(family), final_packet_size);
        } else if(GET_ADDR_TYPE(&network_data) == DLT_EN10MB) {
            memcpy(packet->packet_buffer_start, &eth_hdr, sizeof(eth_hdr));
            memcpy(packet->packet_buffer_start + sizeof(eth_hdr), &ip_header, sizeof(ip_header));
            memcpy(packet->packet_buffer_start + sizeof(eth_hdr) + sizeof(ip_header), &packet_info, sizeof(packet_info));

            memcpy(packet->packet_buffer_start + PACKET_HEADER_SIZE + sizeof(struct ether_header), packet->packet_data_start, packet_length);

            HANDLE_CHECKSUM(packet->packet_buffer_start, final_packet_size, &network_data);

            SWIFTNET_SEND_PACKET(&network_data, packet->packet_buffer_start, final_packet_size);
        }
    }
}

void swiftnet_client_send_packet(struct SwiftNetClientConnection* const client, struct SwiftNetPacketBuffer* restrict const packet) {
    uint32_t packet_length;


    packet_length = packet->packet_append_pointer - packet->packet_data_start;

    swiftnet_send_packet(client, client->maximum_transmission_unit, client->port_info, packet, packet_length, &client->server_addr, &client->packets_sending, &client->packets_sending_memory_allocator, client->eth_header, client->loopback, client->network_data
    #ifdef SWIFT_NET_REQUESTS
        , NULL, false, 0
    #endif
    );
}

void swiftnet_server_send_packet(struct SwiftNetServer* const server, struct SwiftNetPacketBuffer* restrict const packet, const struct SwiftNetClientAddrData target) {
    uint32_t packet_length;
    struct SwiftNetPortInfo port_info;
    struct ether_header eth_hdr;


    packet_length = packet->packet_append_pointer - packet->packet_data_start;

    port_info = (struct SwiftNetPortInfo){
        .destination_port = target.port,
        .source_port = server->server_port
    };

    memcpy(&eth_hdr, &server->eth_header, sizeof(eth_hdr));
    memcpy(&eth_hdr.ether_dhost, &target.mac_address, sizeof(eth_hdr.ether_dhost));

    swiftnet_send_packet(server, target.maximum_transmission_unit, port_info, packet, packet_length, &target.sender_address, &server->packets_sending, &server->packets_sending_memory_allocator, eth_hdr, server->loopback, server->network_data
    #ifdef SWIFT_NET_REQUESTS
        , NULL, false, 0
    #endif
    );
}
