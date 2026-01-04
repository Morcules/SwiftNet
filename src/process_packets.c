#include "internal/internal.h"
#include "swift_net.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

static inline bool is_private_ip(struct in_addr ip) {     
    in_addr_t addr = htonl(ip.s_addr);      
    uint8_t octet1 = (addr >> 24) & 0xFF;
    uint8_t octet2 = (addr >> 16) & 0xFF;
    uint8_t octet3 = (addr >> 8)  & 0xFF;
    uint8_t octet4 = addr & 0xFF;

    return !(octet1 == 192 && octet2 == 168) == false && (octet1 == 127 && octet2 == 0 && octet3 == 0); 
}  

static inline void lock_packet_sending(struct SwiftNetPacketSending* const packet_sending) {
    bool locked = false;
    while(!atomic_compare_exchange_strong_explicit(&packet_sending->locked, &locked, true, memory_order_acquire, memory_order_relaxed)) {
        locked = false;
    }
}

static inline void unlock_packet_sending(struct SwiftNetPacketSending* const packet_sending) {
    atomic_store_explicit(&packet_sending->locked, false, memory_order_release);
}

// Returns an array of 4 byte uint32_tegers, that contain indexes of lost chunks
static inline const uint32_t return_lost_chunk_indexes(const uint8_t* const chunks_received, const uint32_t chunk_amount, const uint32_t buffer_size, uint32_t* const buffer) {
    uint32_t byte = 0;

    uint32_t offset = 0;

    while(1) {
        if(byte * 8 + 8 < chunk_amount) {
            if(chunks_received[byte] == 0xFF) {
                byte++;
                continue;
            }

            for(uint8_t bit = 0; bit < 8; bit++) {
                if(offset * 4 + 4 > buffer_size) { 
                    return buffer_size;
                }

                if((chunks_received[byte] & (1 << bit)) == 0x00) {
                    buffer[offset] = byte * 8 + bit;
                    offset++;
                }
            }
        } else {
            const uint8_t bits_to_check = chunk_amount - byte * 8;
            
            for(uint8_t bit = 0; bit < bits_to_check; bit++) {
                if(offset * 4 + 4 > buffer_size) { 
                    return buffer_size;
                }
                
                if((chunks_received[byte] & (1 << bit)) == 0x00) {
                    buffer[offset] = byte * 8 + bit;
                    offset++;
                }
            }
            
            return offset;
        }

        byte++;
    }

    return offset;
}

static inline void packet_completed(const uint16_t packet_id, struct SwiftNetVector* const packets_completed_history, struct SwiftNetMemoryAllocator* const packets_completed_history_memory_allocator) {
    struct SwiftNetPacketCompleted* const new_packet_completed = allocator_allocate(packets_completed_history_memory_allocator);
    new_packet_completed->packet_id = packet_id;

    vector_lock(packets_completed_history);

    vector_push(packets_completed_history, new_packet_completed);

    vector_unlock(packets_completed_history);

    return;
}

static inline bool check_packet_already_completed(const uint16_t packet_id, struct SwiftNetVector* const packets_completed_history) {
    vector_lock(packets_completed_history);

    for(uint32_t i = 0; i < packets_completed_history->size; i++) {
        const struct SwiftNetPacketCompleted* const current = vector_get((struct SwiftNetVector*)packets_completed_history, i);

        if(current->packet_id == packet_id) {
            vector_unlock(packets_completed_history);

            return true; 
        }
    }

    vector_unlock(packets_completed_history);

    return false;
}

static inline struct SwiftNetPendingMessage* const get_pending_message(struct SwiftNetVector* const pending_messages_vector, const enum ConnectionType connection_type, const struct in_addr sender_address, const uint16_t packet_id) {
    vector_lock(pending_messages_vector);

    for(uint32_t i = 0; i < pending_messages_vector->size; i++) {
        struct SwiftNetPendingMessage* const current_pending_message = vector_get((struct SwiftNetVector*)pending_messages_vector, i);

        if((connection_type == CONNECTION_TYPE_CLIENT && current_pending_message->packet_id == packet_id) || (connection_type == CONNECTION_TYPE_SERVER && current_pending_message->sender_address.s_addr == sender_address.s_addr && current_pending_message->packet_id == packet_id)) {
            vector_unlock((struct SwiftNetVector*)pending_messages_vector);

            return current_pending_message;
        }
    }

    vector_unlock((struct SwiftNetVector*)pending_messages_vector);

    return NULL;
}

static inline void insert_callback_queue_node(struct PacketCallbackQueueNode* const new_node, struct PacketCallbackQueue* const packet_queue) {
    if(unlikely(new_node == NULL)) {
        return;
    }

    uint32_t owner_none = PACKET_CALLBACK_QUEUE_OWNER_NONE;
    while(!atomic_compare_exchange_strong_explicit(&packet_queue->owner, &owner_none, PACKET_CALLBACK_QUEUE_OWNER_PROCESS_PACKETS, memory_order_acquire, memory_order_relaxed)) {
        owner_none = PACKET_CALLBACK_QUEUE_OWNER_NONE;
    }

    if(packet_queue->last_node == NULL) {
        packet_queue->last_node = new_node;
    } else {
        packet_queue->last_node->next = new_node;

        packet_queue->last_node = new_node;
    }

    if(packet_queue->first_node == NULL) {
        packet_queue->first_node = new_node;
    }

    atomic_store_explicit(&packet_queue->owner, PACKET_CALLBACK_QUEUE_OWNER_NONE, memory_order_release);

    return;
}

#ifdef SWIFT_NET_REQUESTS

static inline void handle_request_response(const uint16_t packet_id, const struct in_addr sender, struct SwiftNetPendingMessage* const pending_message, void* const packet_data, struct SwiftNetVector* const pending_messages, struct SwiftNetMemoryAllocator* const pending_message_memory_allocator, const enum ConnectionType connection_type, const bool loopback) {
    bool is_valid_response = false;

    vector_lock(&requests_sent);

    for (uint32_t i = 0; i < requests_sent.size; i++) {
        struct RequestSent* const current_request_sent = vector_get(&requests_sent, i);

        if (current_request_sent == NULL) {
            continue;
        }

        if (current_request_sent->packet_id == packet_id) {
            if (!loopback) {
                if (current_request_sent->address.s_addr != sender.s_addr) {
                    continue;
                }
            }

            atomic_store_explicit(&current_request_sent->packet_data, packet_data, memory_order_release);

            vector_remove(&requests_sent, i);

            is_valid_response = true;

            break;
        }
    }

    vector_unlock(&requests_sent);

    if (is_valid_response == true) {
        if (pending_message != NULL) {
            vector_lock(pending_messages);

            for (uint32_t i = 0; i < pending_messages->size; i++) {
                const struct SwiftNetPendingMessage* const current_pending_message = vector_get(pending_messages, i);
                if (current_pending_message == pending_message) {
                    vector_remove(pending_messages, i);
                }
            }

            vector_unlock(pending_messages);
        }

        return;
    }
}

#endif

static inline void pass_callback_execution(void* const packet_data, struct PacketCallbackQueue* const queue, struct SwiftNetPendingMessage* const pending_message, const uint16_t packet_id) {
    struct PacketCallbackQueueNode* const node = allocator_allocate(&packet_callback_queue_node_memory_allocator);
    node->packet_data = packet_data;
    node->next = NULL;
    node->pending_message = pending_message;
    node->packet_id = packet_id;

    atomic_thread_fence(memory_order_release);

    insert_callback_queue_node(node, queue);
}

static inline bool chunk_already_received(uint8_t* const chunks_received, const uint32_t index) {
    const uint32_t byte = index / 8;
    const uint8_t bit = index % 8;

    return (chunks_received[byte] & (1 << bit)) == 0x01;
}

static inline void chunk_received(uint8_t* const chunks_received, const uint32_t index) {
    const uint32_t byte = index / 8;
    const uint8_t bit = index % 8;

    chunks_received[byte] |= 1 << bit;
}

static inline struct SwiftNetPendingMessage* const create_new_pending_message(struct SwiftNetVector* const pending_messages, struct SwiftNetMemoryAllocator* const pending_messages_memory_allocator, const struct SwiftNetPacketInfo* const packet_info, const enum ConnectionType connection_type, const struct in_addr sender_address, const uint16_t packet_id) {
    struct SwiftNetPendingMessage* const new_pending_message = allocator_allocate(pending_messages_memory_allocator);

    uint8_t* const allocated_memory = malloc(packet_info->packet_length);

    const uint32_t chunks_received_byte_size = (packet_info->chunk_amount + 7) / 8;

    new_pending_message->packet_info = *packet_info;

    new_pending_message->packet_data_start = allocated_memory;
    new_pending_message->chunks_received_number = 0x00;

    new_pending_message->chunks_received_length = chunks_received_byte_size;
    new_pending_message->chunks_received = calloc(chunks_received_byte_size, 1);

    new_pending_message->packet_id = packet_id;

    if(connection_type == CONNECTION_TYPE_SERVER) {
        new_pending_message->sender_address.s_addr = sender_address.s_addr;
    }

    vector_lock(pending_messages);

    vector_push((struct SwiftNetVector*)pending_messages, new_pending_message);

    vector_unlock(pending_messages);

    return new_pending_message;
}

static inline struct SwiftNetPacketSending* const get_packet_sending(struct SwiftNetVector* const packet_sending_array, const uint16_t target_id) {
    vector_lock(packet_sending_array);

    for(uint32_t i = 0; i < packet_sending_array->size; i++) {
        struct SwiftNetPacketSending* const current_packet_sending = vector_get((struct SwiftNetVector*)packet_sending_array, i);

        if(current_packet_sending->packet_id == target_id) {
            vector_unlock(packet_sending_array);

            return current_packet_sending;
        }
    }

    vector_unlock(packet_sending_array);

    return NULL;
}

struct PacketQueueNode* const wait_for_next_packet(struct PacketQueue* const packet_queue) {
    uint32_t owner_none = PACKET_QUEUE_OWNER_NONE;
    while(!atomic_compare_exchange_strong_explicit(&packet_queue->owner, &owner_none, PACKET_QUEUE_OWNER_PROCESS_PACKETS, memory_order_acquire, memory_order_relaxed)) {
        owner_none = PACKET_QUEUE_OWNER_NONE;
    }

    if(packet_queue->first_node == NULL) {
        atomic_store(&packet_queue->owner, PACKET_QUEUE_OWNER_NONE);
        return NULL;
    }

    struct PacketQueueNode* const node_to_process = packet_queue->first_node;

    if(node_to_process->next == NULL) {
        packet_queue->first_node = NULL;
        packet_queue->last_node = NULL;

        atomic_store(&packet_queue->owner, PACKET_QUEUE_OWNER_NONE);

        return node_to_process;
    }

    packet_queue->first_node = node_to_process->next;

    atomic_store_explicit(&packet_queue->owner, PACKET_QUEUE_OWNER_NONE, memory_order_release);

    return node_to_process;
}

static inline bool packet_corrupted(const uint16_t checksum, const uint32_t chunk_size, const uint8_t* const buffer) {
    return crc16(buffer, chunk_size) != checksum;
}

static inline void swiftnet_process_packets(
    void* _Atomic * packet_handler,
    pcap_t* const pcap,
    const struct ether_header eth_hdr,
    const uint16_t source_port,
    const bool loopback,
    const uint16_t addr_type,
    struct SwiftNetVector* const packets_sending,
    struct SwiftNetMemoryAllocator* const packets_sending_messages_memory_allocator,
    struct SwiftNetVector* const pending_messages,
    struct SwiftNetMemoryAllocator* const pending_messages_memory_allocator,
    struct SwiftNetVector* const packets_completed_history,
    struct SwiftNetMemoryAllocator* const packets_completed_history_memory_allocator,
    enum ConnectionType connection_type,
    struct PacketQueue* const packet_queue,
    struct PacketCallbackQueue* const packet_callback_queue,
    void* const connection,
    _Atomic bool* closing,
    const uint8_t prepend_size 
) {
    while(1) {
        if (atomic_load(closing) == true) {
            break;
        }

        struct PacketQueueNode* const node = wait_for_next_packet(packet_queue);
        if(node == NULL) {
            continue;
        }

        atomic_thread_fence(memory_order_acquire);

        uint8_t* const packet_buffer = node->data;
        if(packet_buffer == NULL) {
            goto next_packet;
        }

        uint8_t* const packet_data = &packet_buffer[prepend_size + PACKET_HEADER_SIZE];

        struct ip ip_header;
        memcpy(&ip_header, packet_buffer + prepend_size, sizeof(ip_header));

        struct SwiftNetPacketInfo packet_info;
        memcpy(&packet_info, packet_buffer + prepend_size + sizeof(ip_header), sizeof(packet_info));

        // Check if the packet is meant to be for this server
        if(packet_info.port_info.destination_port != source_port) {
            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            goto next_packet;
        }

        const uint16_t checksum_received = ip_header.ip_sum;

        memset(packet_buffer + prepend_size + offsetof(struct ip, ip_sum), 0x00, SIZEOF_FIELD(struct ip, ip_sum));

        memcpy(packet_buffer + prepend_size + offsetof(struct ip, ip_len), (void*)&node->data_read, SIZEOF_FIELD(struct ip, ip_len));

        if(memcmp(&ip_header.ip_src, &ip_header.ip_dst, sizeof(struct in_addr)) != 0 && is_private_ip(ip_header.ip_src) == false && is_private_ip(ip_header.ip_dst)) { 
            if(ip_header.ip_sum != 0 && packet_corrupted(checksum_received, node->data_read, packet_buffer) == true) {
                #ifdef SWIFT_NET_DEBUG
                    if (check_debug_flag(DEBUG_PACKETS_RECEIVING)) {
                        send_debug_message("Received corrupted packet: {\"source_ip_address\": \"%s\", \"source_port\": %d, \"packet_id\": %d, \"received_checsum\": %d, \"real_checksum\": %d}\n", inet_ntoa(ip_header.ip_src), packet_info.port_info.source_port, ip_header.ip_id, checksum_received, crc16(packet_buffer, node->data_read));
                    }
                #endif

                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                goto next_packet;
            }
        }

        #ifdef SWIFT_NET_DEBUG
            if (check_debug_flag(DEBUG_PACKETS_RECEIVING)) {
                send_debug_message("Received packet: {\"source_ip_address\": \"%s\", \"source_port\": %d, \"packet_id\": %d, \"packet_type\": %d, \"packet_length\": %d, \"chunk_index\": %d, \"connection_type\": %d}\n", inet_ntoa(ip_header.ip_src), packet_info.port_info.source_port, ip_header.ip_id, packet_info.packet_type, packet_info.packet_length, packet_info.chunk_index, connection_type);
            }
        #endif

        switch(packet_info.packet_type) {
            case PACKET_TYPE_REQUEST_INFORMATION:
            {
                const struct ip send_server_info_ip_header = construct_ip_header(node->sender_address, PACKET_HEADER_SIZE, rand());

                const struct SwiftNetPacketInfo packet_info_new = construct_packet_info(
                    sizeof(struct SwiftNetServerInformation),
                    PACKET_TYPE_REQUEST_INFORMATION,
                    1,
                    0,
                    (struct SwiftNetPortInfo){
                        .source_port = source_port,
                        .destination_port = packet_info.port_info.source_port
                    }
                );

                const struct SwiftNetServerInformation server_info = {
                    .maximum_transmission_unit = maximum_transmission_unit
                };

                HANDLE_PACKET_CONSTRUCTION(&send_server_info_ip_header, &packet_info_new, addr_type, &eth_hdr, prepend_size + PACKET_HEADER_SIZE + sizeof(server_info), buffer)

                memcpy(buffer + prepend_size + PACKET_HEADER_SIZE, &server_info, sizeof(server_info));

                HANDLE_CHECKSUM(buffer, sizeof(buffer), prepend_size)
                
                swiftnet_pcap_send(pcap, buffer, sizeof(buffer));

                allocator_free(&packet_buffer_memory_allocator, packet_buffer);
    
                goto next_packet;
            }
            case PACKET_TYPE_SEND_LOST_PACKETS_REQUEST:
            {
                const uint32_t mtu = MIN(packet_info.maximum_transmission_unit, maximum_transmission_unit);

                struct SwiftNetPendingMessage* const pending_message = get_pending_message(pending_messages, connection_type, ip_header.ip_src, ip_header.ip_id);
                if(pending_message == NULL) {
                    const bool packet_already_completed = check_packet_already_completed(ip_header.ip_id, packets_completed_history);
                    if(likely(packet_already_completed == true)) {
                        const struct ip send_packet_ip_header = construct_ip_header(node->sender_address, PACKET_HEADER_SIZE, ip_header.ip_id);

                        struct SwiftNetPacketInfo send_packet_info = construct_packet_info(
                            0x00,
                            PACKET_TYPE_SUCCESSFULLY_RECEIVED_PACKET,
                            1,
                            0,
                            (struct SwiftNetPortInfo){
                                .destination_port = packet_info.port_info.source_port,
                                .source_port = packet_info.port_info.destination_port
                            }
                        );

                        HANDLE_PACKET_CONSTRUCTION(&send_packet_ip_header, &send_packet_info, addr_type, &eth_hdr, prepend_size + PACKET_HEADER_SIZE, buffer)

                        HANDLE_CHECKSUM(buffer, sizeof(buffer), prepend_size)

                        swiftnet_pcap_send(pcap, buffer, sizeof(buffer));

                        allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                        goto next_packet;
                    }

                    allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                    goto next_packet;
                }

                struct ip send_lost_packets_ip_header = construct_ip_header(node->sender_address, 0, ip_header.ip_id);

                struct SwiftNetPacketInfo packet_info_new = construct_packet_info(
                    0,
                    PACKET_TYPE_SEND_LOST_PACKETS_RESPONSE,
                    1,
                    0,
                    (struct SwiftNetPortInfo){
                        .destination_port = packet_info.port_info.source_port,
                        .source_port = packet_info.port_info.destination_port
                    }
                );

                const uint16_t header_size = sizeof(struct ip) + sizeof(struct SwiftNetPacketInfo) + prepend_size;

                HANDLE_PACKET_CONSTRUCTION(&send_lost_packets_ip_header, &packet_info_new, addr_type, &eth_hdr, mtu + prepend_size, buffer)

                const uint16_t lost_chunk_indexes = return_lost_chunk_indexes(pending_message->chunks_received, pending_message->packet_info.chunk_amount, mtu - PACKET_HEADER_SIZE, (uint32_t*)(buffer + header_size));

                const uint16_t packet_length = sizeof(struct ip) + sizeof(struct SwiftNetPacketInfo) + (lost_chunk_indexes * sizeof(uint32_t));
                const uint16_t packet_length_net_order = htons(packet_length);

                memcpy(buffer + prepend_size + offsetof(struct ip, ip_len), &packet_length_net_order, SIZEOF_FIELD(struct ip, ip_len));

                HANDLE_CHECKSUM(buffer, packet_length + prepend_size, prepend_size);

                swiftnet_pcap_send(pcap, buffer, packet_length + prepend_size);

                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                goto next_packet;
            }
            case PACKET_TYPE_SEND_LOST_PACKETS_RESPONSE:
            {
                struct SwiftNetPacketSending* const target_packet_sending = get_packet_sending(packets_sending, ip_header.ip_id);

                if(unlikely(target_packet_sending == NULL)) {
                    allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                    goto next_packet;
                }

                lock_packet_sending(target_packet_sending);

                if(target_packet_sending->lost_chunks == NULL) {
                    target_packet_sending->lost_chunks = malloc(maximum_transmission_unit - PACKET_HEADER_SIZE);
                }

                const uint32_t packets_lost = (packet_info.packet_length) / sizeof(uint32_t);

                memcpy((void*)target_packet_sending->lost_chunks, packet_data, packet_info.packet_length);

                target_packet_sending->lost_chunks_size = packet_info.packet_length / 4;

                atomic_store_explicit(&target_packet_sending->updated, UPDATED_LOST_CHUNKS, memory_order_release);

                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                unlock_packet_sending(target_packet_sending);

                goto next_packet;
            }
            case PACKET_TYPE_SUCCESSFULLY_RECEIVED_PACKET:
            {
                struct SwiftNetPacketSending* const target_packet_sending = get_packet_sending(packets_sending, ip_header.ip_id);

                if(unlikely(target_packet_sending == NULL)) {
                    allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                    goto next_packet;
                }

                atomic_store_explicit(&target_packet_sending->updated, SUCCESSFULLY_RECEIVED, memory_order_release);

                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                goto next_packet;
            }
            default:
                break;
        }

        if (check_packet_already_completed(ip_header.ip_id, packets_completed_history)) {
            allocator_free(&packet_buffer_memory_allocator, packet_buffer);
            goto next_packet;
        }

        struct SwiftNetClientAddrData sender = {
            .sender_address.s_addr = loopback == true ? inet_addr("127.0.0.1") : node->sender_address.s_addr,
            .maximum_transmission_unit = packet_info.maximum_transmission_unit,
            .port = packet_info.port_info.source_port,
        };

        if (addr_type == DLT_EN10MB) {
            memcpy(&sender.mac_address, eth_hdr.ether_shost, sizeof(sender.mac_address));
        }

        const uint32_t mtu = MIN(packet_info.maximum_transmission_unit, maximum_transmission_unit);
        const uint32_t chunk_data_size = mtu - PACKET_HEADER_SIZE;

        struct SwiftNetPendingMessage* const pending_message = get_pending_message(pending_messages, connection_type, node->sender_address, ip_header.ip_id);

        if(pending_message == NULL) {
            if(packet_info.packet_length > chunk_data_size) {
                // Split packet into chunks
                struct SwiftNetPendingMessage* const new_pending_message = create_new_pending_message(pending_messages, pending_messages_memory_allocator, &packet_info, connection_type, node->sender_address, ip_header.ip_id);

                new_pending_message->chunks_received_number++;

                chunk_received(new_pending_message->chunks_received, packet_info.chunk_index);
                    
                memcpy(new_pending_message->packet_data_start, packet_data, chunk_data_size);

                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                goto next_packet;
            } else {
                packet_completed(ip_header.ip_id, packets_completed_history, packets_completed_history_memory_allocator);

                if(connection_type == CONNECTION_TYPE_SERVER) {
                    struct SwiftNetServerPacketData* const new_packet_data = allocator_allocate(&server_packet_data_memory_allocator) ;
                    new_packet_data->data = packet_data;
                    new_packet_data->current_pointer = packet_data;
                    new_packet_data->internal_pending_message = NULL;
                    new_packet_data->metadata = (struct SwiftNetPacketServerMetadata){
                        .port_info = packet_info.port_info,
                        .sender = sender,
                        .data_length = packet_info.packet_length,
                        .packet_id = ip_header.ip_id
                        #ifdef SWIFT_NET_REQUESTS
                            , .expecting_response = packet_info.packet_type == PACKET_TYPE_REQUEST
                        #endif
                    };

                    #ifdef SWIFT_NET_REQUESTS
                    if (packet_info.packet_type == PACKET_TYPE_RESPONSE) {
                        handle_request_response(ip_header.ip_id, sender.sender_address, NULL, new_packet_data, pending_messages, pending_messages_memory_allocator, connection_type, loopback);
                    } else {
                        pass_callback_execution(new_packet_data, packet_callback_queue, NULL, ip_header.ip_id);
                    }
                    #else
                        pass_callback_execution(new_packet_data, packet_callback_queue, NULL, ip_header.ip_id);
                    #endif
                } else {
                    struct SwiftNetClientPacketData* const new_packet_data = allocator_allocate(&client_packet_data_memory_allocator) ;
                    new_packet_data->data = packet_data;
                    new_packet_data->current_pointer = packet_data;
                    new_packet_data->internal_pending_message = NULL;
                    new_packet_data->metadata = (struct SwiftNetPacketClientMetadata){
                        .port_info = packet_info.port_info,
                        .data_length = packet_info.packet_length,
                        .packet_id = ip_header.ip_id
                        #ifdef SWIFT_NET_REQUESTS
                            , .expecting_response = packet_info.packet_type == PACKET_TYPE_REQUEST
                        #endif
                    };

                    #ifdef SWIFT_NET_REQUESTS
                    if (packet_info.packet_type == PACKET_TYPE_RESPONSE) {
                        handle_request_response(ip_header.ip_id, ((struct SwiftNetClientConnection*)connection)->server_addr, NULL, new_packet_data, pending_messages, pending_messages_memory_allocator, connection_type, loopback);
                    } else {
                        pass_callback_execution(new_packet_data, packet_callback_queue, NULL, ip_header.ip_id);
                    }
                    #else
                        pass_callback_execution(new_packet_data, packet_callback_queue, NULL, ip_header.ip_id);
                    #endif
                }

                goto next_packet;
            }
        } else {
            if (chunk_already_received(pending_message->chunks_received, packet_info.chunk_index)) {
                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                goto next_packet;
            }

            const uint32_t bytes_to_write = (packet_info.chunk_index + 1) >= packet_info.chunk_amount ? packet_info.packet_length % chunk_data_size : chunk_data_size;

            if(pending_message->chunks_received_number + 1 >= packet_info.chunk_amount) {
                // Completed the packet
                memcpy(pending_message->packet_data_start + (chunk_data_size * packet_info.chunk_index), packet_data, bytes_to_write);

                chunk_received(pending_message->chunks_received, packet_info.chunk_index);

                #ifdef SWIFT_NET_DEBUG
                    uint32_t lost_chunks_buffer[chunk_data_size];

                    const uint32_t lost_chunks_num = return_lost_chunk_indexes(pending_message->chunks_received, packet_info.chunk_amount, chunk_data_size, (uint32_t*)lost_chunks_buffer);

                    if (lost_chunks_num != 0) {
                        PRINT_ERROR("Packet marked as completed, but %d chunks are missing", lost_chunks_num);

                        for (uint32_t i = 0; i < lost_chunks_num; i++) {
                            printf("chunk index missing: %d\n", *(lost_chunks_buffer + i));  
                        }
                    }
                #endif

                packet_completed(ip_header.ip_id, packets_completed_history, packets_completed_history_memory_allocator);

                if(connection_type == CONNECTION_TYPE_SERVER) {
                    uint8_t* const ptr = pending_message->packet_data_start;

                    struct SwiftNetServerPacketData* const packet_data = allocator_allocate(&server_packet_data_memory_allocator);
                    packet_data->data = ptr;
                    packet_data->current_pointer = ptr;
                    packet_data->internal_pending_message = pending_message;
                    packet_data->metadata = (struct SwiftNetPacketServerMetadata){
                        .port_info = packet_info.port_info,
                        .sender = sender,
                        .data_length = packet_info.packet_length,
                        .packet_id = ip_header.ip_id
                        #ifdef SWIFT_NET_REQUESTS
                            , .expecting_response = packet_info.packet_type == PACKET_TYPE_REQUEST
                        #endif
                    };

                    #ifdef SWIFT_NET_REQUESTS
                    if (packet_info.packet_type == PACKET_TYPE_RESPONSE) {
                        handle_request_response(ip_header.ip_id, sender.sender_address, pending_message, packet_data, pending_messages, pending_messages_memory_allocator, connection_type, loopback);
                    } else {
                        pass_callback_execution(packet_data, packet_callback_queue, pending_message, ip_header.ip_id);
                    }
                    #else
                        pass_callback_execution(packet_data, packet_callback_queue, pending_message, ip_header.ip_id);
                    #endif
                } else {
                    uint8_t* const ptr = pending_message->packet_data_start;

                    struct SwiftNetClientPacketData* const packet_data = allocator_allocate(&client_packet_data_memory_allocator) ;
                    packet_data->data = ptr;
                    packet_data->current_pointer = ptr;
                    packet_data->internal_pending_message = pending_message;
                    packet_data->metadata = (struct SwiftNetPacketClientMetadata){
                        .port_info = packet_info.port_info,
                        .data_length = packet_info.packet_length,
                        .packet_id = ip_header.ip_id
                        #ifdef SWIFT_NET_REQUESTS
                            , .expecting_response = packet_info.packet_type == PACKET_TYPE_REQUEST
                        #endif
                    };

                    #ifdef SWIFT_NET_REQUESTS
                    if (packet_info.packet_type == PACKET_TYPE_RESPONSE) {
                        handle_request_response(ip_header.ip_id, ((struct SwiftNetClientConnection*)connection)->server_addr, pending_message, packet_data, pending_messages, pending_messages_memory_allocator, connection_type, loopback);
                    } else {
                        pass_callback_execution(packet_data, packet_callback_queue, pending_message, ip_header.ip_id);
                    }
                    #else
                        pass_callback_execution(packet_data, packet_callback_queue, pending_message, ip_header.ip_id);
                    #endif
                }

                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                goto next_packet;
            } else {
                memcpy(pending_message->packet_data_start + (chunk_data_size * packet_info.chunk_index), packet_data, bytes_to_write);

                chunk_received(pending_message->chunks_received, packet_info.chunk_index);

                pending_message->chunks_received_number++;

                atomic_thread_fence(memory_order_release);

                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                goto next_packet;
            }
        }

        goto next_packet;

    next_packet:
        allocator_free(&packet_queue_node_memory_allocator, (void*)node);

        continue;
    }
}

void* swiftnet_server_process_packets(void* const void_server) {
    struct SwiftNetServer* const server = (struct SwiftNetServer*)void_server;

    swiftnet_process_packets((void*)&server->packet_handler, server->pcap, server->eth_header, server->server_port, server->loopback, server->addr_type, &server->packets_sending, &server->packets_sending_memory_allocator, &server->pending_messages, &server->pending_messages_memory_allocator, &server->packets_completed, &server->packets_completed_memory_allocator, CONNECTION_TYPE_SERVER, &server->packet_queue, &server->packet_callback_queue, server, &server->closing, server->prepend_size);

    return NULL;
}

void* swiftnet_client_process_packets(void* const void_client) {
    struct SwiftNetClientConnection* const client = (struct SwiftNetClientConnection*)void_client;

    swiftnet_process_packets((void*)&client->packet_handler, client->pcap, client->eth_header, client->port_info.source_port, client->loopback, client->addr_type, &client->packets_sending, &client->packets_sending_memory_allocator, &client->pending_messages, &client->pending_messages_memory_allocator, &client->packets_completed, &client->packets_completed_memory_allocator, CONNECTION_TYPE_CLIENT, &client->packet_queue, &client->packet_callback_queue, client, &client->closing, client->prepend_size);

    return NULL;
}
