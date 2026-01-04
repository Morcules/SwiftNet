#include "swift_net.h"
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

static inline void lock_packet_sending(struct SwiftNetPacketSending* const packet_sending) {
    bool locked = false;
    while(!atomic_compare_exchange_strong_explicit(&packet_sending->locked, &locked, true, memory_order_acquire, memory_order_relaxed)) {
        locked = false;
    }
}

static inline void unlock_packet_sending(struct SwiftNetPacketSending* const packet_sending) {
    atomic_store_explicit(&packet_sending->locked, false, memory_order_release);
}

static inline uint8_t request_lost_packets_bitarray(const uint8_t* const raw_data, const uint32_t data_size, const struct sockaddr* const destination, pcap_t* const pcap, struct SwiftNetPacketSending* const packet_sending) {
    while(1) {
        if(check_debug_flag(DEBUG_LOST_PACKETS)) {
            send_debug_message("Requested list of lost packets: {\"packet_id\": %d}\n", packet_sending->packet_id);
        }

        swiftnet_pcap_send(pcap, raw_data, data_size);

        for(uint8_t times_checked = 0; times_checked < 0xFF; times_checked++) {
            const enum PacketSendingUpdated status = atomic_load_explicit(&packet_sending->updated, memory_order_acquire);

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
    }
}

static inline void handle_lost_packets(
    struct SwiftNetPacketSending* const packet_sending,
    const uint32_t mtu,
    const struct SwiftNetPacketBuffer* const packet, 
    pcap_t* pcap,
    const struct ether_header eth_hdr,
    const struct in_addr* const destination_address,
    const uint16_t source_port,
    const uint16_t destination_port,
    struct SwiftNetMemoryAllocator* const packets_sending_memory_allocator,
    struct SwiftNetVector* const packets_sending,
    const bool loopback,
    const uint16_t addr_type,
    const uint8_t prepend_size
    #ifdef SWIFT_NET_REQUESTS
        , const bool response
        , const uint8_t packet_type
    #endif
) {
    const struct SwiftNetPortInfo port_info = {
        .source_port = source_port,
        .destination_port = destination_port
    };

    const struct ip request_lost_packets_ip_header = construct_ip_header(*destination_address, PACKET_HEADER_SIZE, packet_sending->packet_id);

    struct SwiftNetPacketInfo request_lost_packets_bit_array = construct_packet_info(
        0x00,
        PACKET_TYPE_SEND_LOST_PACKETS_REQUEST,
        1,
        0,
        port_info
    );

    HANDLE_PACKET_CONSTRUCTION(&request_lost_packets_ip_header, &request_lost_packets_bit_array, addr_type, &eth_hdr, PACKET_HEADER_SIZE + prepend_size, request_lost_packets_buffer)
 
    HANDLE_CHECKSUM(request_lost_packets_buffer, sizeof(request_lost_packets_buffer), prepend_size)
 
    const uint32_t packet_length = packet->packet_append_pointer - packet->packet_data_start;
    const uint32_t chunk_amount = (packet_length + (mtu - PACKET_HEADER_SIZE) - 1) / (mtu - PACKET_HEADER_SIZE);

    const struct SwiftNetPacketInfo resend_chunk_packet_info = construct_packet_info(
        packet_length,
        #ifdef SWIFT_NET_REQUESTS
        packet_type,
        #else
        PACKET_TYPE_MESSAGE,
        #endif
        chunk_amount,
        0,
        port_info
    );
 
    const struct ip resend_chunk_ip_header = construct_ip_header(*destination_address, mtu, packet_sending->packet_id);

    HANDLE_PACKET_CONSTRUCTION(&resend_chunk_ip_header, &resend_chunk_packet_info, addr_type, &eth_hdr, mtu + prepend_size, resend_chunk_buffer)

    while(1) {
        const uint8_t request_lost_packets_bitarray_response = request_lost_packets_bitarray(request_lost_packets_buffer, PACKET_HEADER_SIZE + prepend_size, (const struct sockaddr*)destination_address, pcap, packet_sending);

        lock_packet_sending(packet_sending);

        switch (request_lost_packets_bitarray_response) {
            case REQUEST_LOST_PACKETS_RETURN_UPDATED_BIT_ARRAY:
                break;
            case REQUEST_LOST_PACKETS_RETURN_COMPLETED_PACKET:
                free((void*)packet_sending->lost_chunks);

                vector_lock(packets_sending);

                for (uint32_t i = 0; i < packets_sending->size; i++) {
                    if (((struct SwiftNetPacketSending*)vector_get(packets_sending, i))->packet_id == packet_sending->packet_id) {
                        vector_remove(packets_sending, i);

                        break;
                    }
                }

                vector_unlock(packets_sending);

                unlock_packet_sending(packet_sending);

                allocator_free(packets_sending_memory_allocator, packet_sending);

                return;
        }
    
        for(uint32_t i = 0; i < packet_sending->lost_chunks_size; i++) {
            const uint32_t lost_chunk_index = packet_sending->lost_chunks[i];

            if (check_debug_flag(DEBUG_LOST_PACKETS) == true) {
                send_debug_message("Packet lost: {\"packet_id\": %d, \"chunk index\": %d}\n", packet_sending->packet_id, lost_chunk_index);
            }
    
            memcpy(&resend_chunk_buffer[sizeof(struct ip) + prepend_size + offsetof(struct SwiftNetPacketInfo, chunk_index)], &lost_chunk_index, SIZEOF_FIELD(struct SwiftNetPacketInfo, chunk_index));
    
            const uint32_t current_offset = lost_chunk_index * (mtu - PACKET_HEADER_SIZE);

            const uint16_t null_sum = htons(0);
            memcpy(&resend_chunk_buffer[prepend_size + offsetof(struct ip, ip_sum)], &null_sum, SIZEOF_FIELD(struct ip, ip_sum));

            if(current_offset + mtu - PACKET_HEADER_SIZE >= packet_length) {
                const uint32_t bytes_to_complete = packet_length - current_offset;

                const uint16_t new_ip_len = htons(bytes_to_complete + PACKET_HEADER_SIZE);
                memcpy(&resend_chunk_buffer[offsetof(struct ip, ip_len)], &new_ip_len, SIZEOF_FIELD(struct ip, ip_len));
                
                memcpy(&resend_chunk_buffer + PACKET_HEADER_SIZE + prepend_size, &packet->packet_data_start[current_offset], bytes_to_complete);
    
                HANDLE_CHECKSUM(resend_chunk_buffer, prepend_size + PACKET_HEADER_SIZE + bytes_to_complete, prepend_size)
    
                swiftnet_pcap_send(pcap, resend_chunk_buffer, bytes_to_complete + PACKET_HEADER_SIZE + prepend_size);
            } else {
                memcpy(&resend_chunk_buffer + PACKET_HEADER_SIZE + prepend_size, &packet->packet_data_start[current_offset], mtu - PACKET_HEADER_SIZE);

                HANDLE_CHECKSUM(resend_chunk_buffer, mtu + prepend_size, prepend_size)

                swiftnet_pcap_send(pcap, resend_chunk_buffer, mtu + prepend_size);
            }
        }

        unlock_packet_sending(packet_sending);
    }
}

inline void swiftnet_send_packet(
    const void* const connection,
    const uint32_t target_maximum_transmission_unit,
    const struct SwiftNetPortInfo port_info,
    const struct SwiftNetPacketBuffer* const packet,
    const uint32_t packet_length,
    const struct in_addr* const target_addr,
    struct SwiftNetVector* const packets_sending,
    struct SwiftNetMemoryAllocator* const packets_sending_memory_allocator,
    pcap_t* const pcap,
    const struct ether_header eth_hdr,
    const bool loopback,
    const uint16_t addr_type,
    const uint8_t prepend_size
    #ifdef SWIFT_NET_REQUESTS
        , struct RequestSent* const request_sent
        , const bool response
        , const uint16_t request_packet_id
    #endif
) {
    const uint32_t mtu = MIN(target_maximum_transmission_unit, maximum_transmission_unit);

    #ifdef SWIFT_NET_DEBUG
        if (check_debug_flag(DEBUG_PACKETS_SENDING)) {
            send_debug_message("Sending packet: {\"destination_ip_address\": \"%s\", \"destination_port\": %d, \"packet_length\": %d}\n", inet_ntoa(*target_addr), port_info.destination_port, packet_length);
        }
    #endif

    #ifdef SWIFT_NET_REQUESTS
        uint16_t packet_id;
        if (response == true) {
            packet_id = request_packet_id;
        } else {
            packet_id = rand();
        }

        if (request_sent != NULL) {
            request_sent->packet_id = packet_id;

            vector_lock(&requests_sent);

            vector_push(&requests_sent, request_sent);

            vector_unlock(&requests_sent);
        }
    #else
        const uint16_t packet_id = rand();
    #endif

    #ifdef SWIFT_NET_REQUESTS
    const uint8_t packet_type = response ? PACKET_TYPE_RESPONSE : request_sent == NULL ? PACKET_TYPE_MESSAGE : PACKET_TYPE_REQUEST;
    #endif

    const uint32_t chunk_amount = (packet_length + (mtu - PACKET_HEADER_SIZE) - 1) / (mtu - PACKET_HEADER_SIZE);

    if(packet_length > mtu) {
        struct SwiftNetPacketInfo packet_info = construct_packet_info(
            packet_length,
            #ifdef SWIFT_NET_REQUESTS
            packet_type,
            #else
            PACKET_TYPE_MESSAGE,
            #endif
            chunk_amount,
            0,
            port_info
        );

        const struct ip ip_header = construct_ip_header(*target_addr, mtu, packet_id);

        struct SwiftNetPacketSending* const new_packet_sending = allocator_allocate(packets_sending_memory_allocator);
        if(unlikely(new_packet_sending == NULL)) {
            PRINT_ERROR("Failed to send a packet: exceeded maximum amount of sending packets at the same time");
            return;
        }

        vector_lock(packets_sending);

        vector_push((struct SwiftNetVector*)packets_sending, (struct SwiftNetPacketSending*)new_packet_sending);

        vector_unlock(packets_sending);

        new_packet_sending->lost_chunks = NULL;
        new_packet_sending->locked = false;
        new_packet_sending->lost_chunks = NULL;
        new_packet_sending->lost_chunks_size = 0;
        new_packet_sending->packet_id = packet_id;

        HANDLE_PACKET_CONSTRUCTION(&ip_header, &packet_info, addr_type, &eth_hdr, mtu + prepend_size, buffer)

        for(uint32_t i = 0; ; i++) {
            const uint32_t current_offset = i * (mtu - PACKET_HEADER_SIZE);

            #ifdef SWIFT_NET_DEBUG
                if (check_debug_flag(DEBUG_PACKETS_SENDING)) {
                    send_debug_message("Sent chunk: {\"chunk_index\": %d}\n", i);
                }
            #endif

            memcpy(&buffer[sizeof(struct ip) + prepend_size + offsetof(struct SwiftNetPacketInfo, chunk_index)], &i, SIZEOF_FIELD(struct SwiftNetPacketInfo, chunk_index));
            
            const uint16_t null_sum = htons(0);
            memcpy(&buffer[prepend_size + offsetof(struct ip, ip_sum)], &null_sum, SIZEOF_FIELD(struct ip, ip_sum));
        
            if(current_offset + (mtu - PACKET_HEADER_SIZE) >= packet_info.packet_length) {
                // Last chunk
                const uint16_t bytes_to_send = (uint16_t)packet_length - current_offset + PACKET_HEADER_SIZE + prepend_size;
		const uint16_t bytes_to_send_net_order = htons(bytes_to_send - prepend_size);

                memcpy(&buffer[PACKET_HEADER_SIZE + prepend_size], packet->packet_data_start + current_offset, bytes_to_send - prepend_size - PACKET_HEADER_SIZE);
                memcpy(&buffer[prepend_size + offsetof(struct ip, ip_len)], &bytes_to_send_net_order, SIZEOF_FIELD(struct ip, ip_len));

                HANDLE_CHECKSUM(buffer, bytes_to_send, prepend_size)

                swiftnet_pcap_send(pcap, buffer, bytes_to_send);

                handle_lost_packets(new_packet_sending, mtu, packet, pcap, eth_hdr, target_addr, port_info.source_port, port_info.destination_port, packets_sending_memory_allocator, packets_sending, loopback, addr_type, prepend_size
                #ifdef SWIFT_NET_REQUESTS
                    , response
                    , packet_type
                #endif
                );
                
                break;
            } else {
                memcpy(buffer + PACKET_HEADER_SIZE + prepend_size, packet->packet_data_start + current_offset, mtu - PACKET_HEADER_SIZE);

                HANDLE_CHECKSUM(buffer, sizeof(buffer), prepend_size)

                swiftnet_pcap_send(pcap, buffer, sizeof(buffer));
            }
        }
    } else {
        const uint32_t final_packet_size = prepend_size + PACKET_HEADER_SIZE + packet_length;

        const struct SwiftNetPacketInfo packet_info = construct_packet_info(
            packet_length,
            #ifdef SWIFT_NET_REQUESTS
            packet_type,
            #else
            PACKET_TYPE_MESSAGE,
            #endif
            1,
            0,
            port_info
        );

        const struct ip ip_header = construct_ip_header(*target_addr, final_packet_size - prepend_size, packet_id);

        if(addr_type == DLT_NULL) {
            uint32_t family = PF_INET;
            memcpy(packet->packet_buffer_start + sizeof(struct ether_header) - sizeof(family), &family, sizeof(family));
            memcpy(packet->packet_buffer_start + sizeof(struct ether_header), &ip_header, sizeof(ip_header));
            memcpy(packet->packet_buffer_start + sizeof(struct ether_header) + sizeof(struct ip), &packet_info, sizeof(packet_info));

            memcpy(packet->packet_buffer_start + PACKET_HEADER_SIZE + sizeof(struct ether_header), packet->packet_data_start, packet_length);

            HANDLE_CHECKSUM(packet->packet_buffer_start + sizeof(struct ether_header) - sizeof(family), final_packet_size, prepend_size)

            swiftnet_pcap_send(pcap, packet->packet_buffer_start + sizeof(struct ether_header) - sizeof(family), final_packet_size);
        } else if(addr_type == DLT_EN10MB) {
            memcpy(packet->packet_buffer_start, &eth_hdr, sizeof(eth_hdr));
            memcpy(packet->packet_buffer_start + sizeof(eth_hdr), &ip_header, sizeof(ip_header));
            memcpy(packet->packet_buffer_start + sizeof(eth_hdr) + sizeof(ip_header), &packet_info, sizeof(packet_info));

            memcpy(packet->packet_buffer_start + PACKET_HEADER_SIZE + sizeof(struct ether_header), packet->packet_data_start, packet_length);

            HANDLE_CHECKSUM(packet->packet_buffer_start, final_packet_size, prepend_size)

            swiftnet_pcap_send(pcap, packet->packet_buffer_start, final_packet_size);
        }
    }
}

void swiftnet_client_send_packet(struct SwiftNetClientConnection* const client, struct SwiftNetPacketBuffer* const packet) {
    const uint32_t packet_length = packet->packet_append_pointer - packet->packet_data_start;

    swiftnet_send_packet(client, client->maximum_transmission_unit, client->port_info, packet, packet_length, &client->server_addr, &client->packets_sending, &client->packets_sending_memory_allocator, client->pcap, client->eth_header, client->loopback, client->addr_type, client->prepend_size
    #ifdef SWIFT_NET_REQUESTS
        , NULL, false, 0
    #endif
    );
}

void swiftnet_server_send_packet(struct SwiftNetServer* const server, struct SwiftNetPacketBuffer* const packet, const struct SwiftNetClientAddrData target) {
    const uint32_t packet_length = packet->packet_append_pointer - packet->packet_data_start;

    const struct SwiftNetPortInfo port_info = {
        .destination_port = target.port,
        .source_port = server->server_port
    };

    struct ether_header eth_hdr;
    memcpy(&eth_hdr, &server->eth_header, sizeof(eth_hdr));
    memcpy(&eth_hdr.ether_dhost, &target.mac_address, sizeof(eth_hdr.ether_dhost));

    swiftnet_send_packet(server, target.maximum_transmission_unit, port_info, packet, packet_length, &target.sender_address, &server->packets_sending, &server->packets_sending_memory_allocator, server->pcap, eth_hdr, server->loopback, server->addr_type, server->prepend_size
    #ifdef SWIFT_NET_REQUESTS
        , NULL, false, 0
    #endif
    );
}
