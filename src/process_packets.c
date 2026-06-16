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
#include <sys/cdefs.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

static inline bool is_private_ip(const struct in_addr ip) {     
    in_addr_t addr = htonl(ip.s_addr);      
    uint8_t octet1 = (addr >> 24) & 0xFF;
    uint8_t octet2 = (addr >> 16) & 0xFF;
    uint8_t octet3 = (addr >> 8)  & 0xFF;
    uint8_t octet4 = addr & 0xFF;

    return !(octet1 == 192 && octet2 == 168) == false && (octet1 == 127 && octet2 == 0 && octet3 == 0); 
}  

// Returns an array of 4 byte uint32_t, that contain indexes of lost chunks
static inline uint32_t return_lost_chunk_indexes(const uint8_t* restrict const chunks_received, const uint32_t chunk_amount, const uint32_t buffer_size, uint32_t* restrict const buffer) {
    uint32_t byte = 0;
    uint32_t offset = 0;

    goto loop;

loop:
    if(byte * 8 + 8 < chunk_amount) {
        if(chunks_received[byte] == 0xFF) {
            byte++;
            
            goto loop;
        }

        for(uint8_t bit = 0; bit < 8; bit++) {
            if(offset * 4 + 4 > buffer_size) goto exit;

            if((chunks_received[byte] & (1u << bit)) == 0x00) {
                buffer[offset] = byte * 8 + bit;
                offset++;
            }
        }
    } else {
        for(uint32_t bit = 0; bit < chunk_amount - byte * 8; bit++) {
            if(offset * 4 + 4 > buffer_size) goto exit;
            
            if((chunks_received[byte] & (1u << bit)) == 0x00) {
                buffer[offset] = byte * 8 + bit;
                offset++;
            }
        }
        
        goto exit;
    }

    byte++;

    goto loop;


exit:
    return offset;
}

static inline void packet_completed(const uint16_t packet_id, const uint16_t source_port, struct SwiftNetHashMap* const packets_completed_history, struct SwiftNetMemoryAllocator* const packets_completed_history_memory_allocator) {
    struct SwiftNetPacketCompleted* new_packet_completed;
    struct PacketCompletedKey* key;
    uint16_t* heap_key_data_location;


    new_packet_completed = allocator_allocate(packets_completed_history_memory_allocator);
    *new_packet_completed = (struct SwiftNetPacketCompleted){.packet_id = packet_id, .marked_cleanup = false};

    heap_key_data_location = allocator_allocate(&uint16_memory_allocator);
    *heap_key_data_location = packet_id;

    LOCK_ATOMIC_DATA_TYPE(&packets_completed_history->atomic_lock);

    key = allocator_allocate(&packet_completed_key_allocator);
    *key = (struct PacketCompletedKey){
        .source_port = source_port,
        .packet_id = packet_id
    };

    hashmap_insert(key, sizeof(struct PacketCompletedKey), new_packet_completed, packets_completed_history);
    
    UNLOCK_ATOMIC_DATA_TYPE(&packets_completed_history->atomic_lock);

    return;
}

static inline bool check_packet_already_completed(const uint16_t packet_id, const uint16_t source_port, struct SwiftNetHashMap* const packets_completed_history) {
    struct PacketCompletedKey key;
    struct SwiftNetPacketCompleted* item;


    key = (struct PacketCompletedKey){.packet_id = packet_id, .source_port = source_port};

    item = hashmap_get(&key, sizeof(key), packets_completed_history);

    return item != NULL;
}

static inline struct SwiftNetPendingMessage* get_pending_message(struct SwiftNetHashMap* const pending_messages, const enum ConnectionType connection_type, const uint16_t packet_id, const uint16_t source_port) {
    struct PendingMessagesKey key;
    struct SwiftNetPendingMessage* pending_message;


    LOCK_ATOMIC_DATA_TYPE(&pending_messages->atomic_lock);

    key = (struct PendingMessagesKey){.source_port = source_port, .packet_id = packet_id};

    pending_message = hashmap_get(&key, sizeof(key), pending_messages);

    UNLOCK_ATOMIC_DATA_TYPE(&pending_messages->atomic_lock);

    return pending_message;
}

static inline void insert_callback_queue_node(struct PacketCallbackQueueNode* restrict const new_node, struct PacketCallbackQueue* const packet_queue) {
    if(unlikely(new_node == NULL)) return;

    LOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

    if(packet_queue->last_node == NULL) {
        packet_queue->last_node = new_node;
    } else {
        packet_queue->last_node->next = new_node;

        packet_queue->last_node = new_node;
    }

    if(packet_queue->first_node == NULL) {
        packet_queue->first_node = new_node;
    }

    UNLOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

    return;
}

#ifdef SWIFT_NET_REQUESTS

static inline void handle_request_response(uint16_t packet_id, const struct SwiftNetPendingMessage* restrict const pending_message, void* restrict const packet_data, struct SwiftNetHashMap* const pending_messages, struct SwiftNetMemoryAllocator* const pending_message_memory_allocator, const enum ConnectionType connection_type, const bool loopback, const uint16_t source_port) {
    struct RequestSent* request_sent;

    LOCK_ATOMIC_DATA_TYPE(&requests_sent.atomic_lock);

    request_sent = hashmap_get(&packet_id, sizeof(uint16_t), &requests_sent);
    if (request_sent == NULL) {
        UNLOCK_ATOMIC_DATA_TYPE(&requests_sent.atomic_lock);
        return;
    }

    atomic_store_explicit(&request_sent->packet_data, packet_data, memory_order_release);

    hashmap_remove(&packet_id, sizeof(uint16_t), &requests_sent);

    UNLOCK_ATOMIC_DATA_TYPE(&requests_sent.atomic_lock);

    if (pending_message != NULL) {
        struct PendingMessagesKey key;


        key = (struct PendingMessagesKey){.source_port = source_port, .packet_id = packet_id};

        LOCK_ATOMIC_DATA_TYPE(&pending_messages->atomic_lock);

        hashmap_remove(&key, sizeof(key), pending_messages);

        UNLOCK_ATOMIC_DATA_TYPE(&pending_messages->atomic_lock);

        return;
    } else return;
}

#endif

static inline void pass_callback_execution(void* const packet_data, struct PacketCallbackQueue* const queue, struct SwiftNetPendingMessage* restrict const pending_message, const uint16_t packet_id, pthread_mutex_t* const execute_callback_mtx, pthread_cond_t* const execute_callback_cond) {
    struct PacketCallbackQueueNode* node;


    node = allocator_allocate(&packet_callback_queue_node_memory_allocator);
    *node = (struct PacketCallbackQueueNode){.packet_data = packet_data, .next = NULL, .pending_message = pending_message, .packet_id = packet_id};

    pthread_mutex_lock(execute_callback_mtx);

    insert_callback_queue_node(node, queue);

    pthread_cond_signal(execute_callback_cond);

    pthread_mutex_unlock(execute_callback_mtx);
}

static inline bool chunk_already_received(const uint8_t* restrict const chunks_received, const uint32_t index) {
    return (chunks_received[index / 8] & (1U << (index % 8))) != 0;
}

static inline void chunk_received(uint8_t* restrict const chunks_received, const uint32_t index) {
    uint32_t byte;
    uint8_t bit;

    byte = index / 8;
    bit = index % 8;

    chunks_received[byte] |= (uint8_t)(1U << bit);
}

static inline struct SwiftNetPendingMessage* create_new_pending_message(struct SwiftNetHashMap* const pending_messages, struct SwiftNetMemoryAllocator* const pending_messages_memory_allocator, const struct SwiftNetPacketInfo* restrict const packet_info, const enum ConnectionType connection_type, const uint16_t packet_id, const uint16_t source_port) {
    struct SwiftNetPendingMessage* new_pending_message;
    uint8_t* allocated_memory;
    struct PendingMessagesKey* key;
    uint32_t chunks_received_byte_size;


    chunks_received_byte_size = (packet_info->chunk_amount + 7) / 8;

    new_pending_message = allocator_allocate(pending_messages_memory_allocator);

    allocated_memory = malloc(packet_info->packet_length);

    *new_pending_message = (struct SwiftNetPendingMessage){
        .packet_info = *packet_info,
        .packet_data_start = allocated_memory,
        .chunks_received_number = 0x00,
        .last_index_checked = 0,
        .sending_lost_packets = false,
        .last_chunks_received_number = 0,
        .chunks_received_length = chunks_received_byte_size,
        .chunks_received = calloc(chunks_received_byte_size, 1),
        .packet_id = packet_id,
        .source_port = source_port,
    };

    LOCK_ATOMIC_DATA_TYPE(&pending_messages->atomic_lock);

    key = allocator_allocate(&pending_message_key_allocator);
    *key = (struct PendingMessagesKey){
        .source_port = source_port,
        .packet_id = packet_id
    };

    hashmap_insert(key, sizeof(struct PendingMessagesKey), new_pending_message, pending_messages);

    UNLOCK_ATOMIC_DATA_TYPE(&pending_messages->atomic_lock);

    return new_pending_message;
}

static inline struct SwiftNetPacketSending* get_packet_sending(struct SwiftNetHashMap* const packet_sending_array, const uint16_t target_id) {
    struct SwiftNetPacketSending* result;


    LOCK_ATOMIC_DATA_TYPE(&packet_sending_array->atomic_lock);

    result = hashmap_get(&target_id, sizeof(target_id), packet_sending_array);

    UNLOCK_ATOMIC_DATA_TYPE(&packet_sending_array->atomic_lock);

    return result;
}

static inline void signal_delay_change(const enum PacketDelayUpdateStatus status, const struct ip* restrict const ip_header, const uint16_t source_port, const uint16_t destination_port, const uint16_t addr_type, const uint8_t prepend_size, pcap_t* const pcap, const struct ether_header* restrict const eth_hdr) {
    struct ip send_server_info_ip_header;
    struct SwiftNetPacketInfo packet_info_new;
    struct SwiftNetServerInformation server_info;


    send_server_info_ip_header = construct_ip_header(ip_header->ip_src, PACKET_HEADER_SIZE, ip_header->ip_id);

    packet_info_new = construct_packet_info(
        sizeof(enum PacketDelayUpdateStatus),
        PACKET_DELAY_UPDATE,
        1,
        0,
        (struct SwiftNetPortInfo){
            .source_port = source_port,
            .destination_port = destination_port
        }
    );

    server_info = (struct SwiftNetServerInformation){
        .maximum_transmission_unit = maximum_transmission_unit
    };

    HANDLE_PACKET_CONSTRUCTION(&send_server_info_ip_header, &packet_info_new, addr_type, eth_hdr, prepend_size + PACKET_HEADER_SIZE + sizeof(server_info), buffer)

    memcpy(buffer + prepend_size + PACKET_HEADER_SIZE, &server_info, sizeof(server_info));

    HANDLE_CHECKSUM(buffer, sizeof(buffer), prepend_size)
    
    SWIFTNET_PCAP_SEND_SAFE(pcap, buffer, sizeof(buffer));
}

struct PacketQueueNode* wait_for_next_packet(struct PacketQueue* const packet_queue) {
    struct PacketQueueNode* node_to_process;


    LOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

    if(packet_queue->first_node == NULL) {
        UNLOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);
        return NULL;
    }

    node_to_process = packet_queue->first_node;

    if(node_to_process->next == NULL) {
        packet_queue->first_node = NULL;
        packet_queue->last_node = NULL;

        UNLOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

        return node_to_process;
    }

    packet_queue->first_node = node_to_process->next;

    UNLOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

    return node_to_process;
}

static inline bool packet_corrupted(const uint32_t checksum, const uint32_t chunk_size, uint8_t* restrict const buffer) {
    return crc32(buffer, chunk_size) != checksum;
}

static inline void swiftnet_process_packets(
    void* _Atomic * const packet_handler,
    pcap_t* const pcap,
    const struct ether_header eth_hdr,
    const uint16_t source_port,
    const bool loopback,
    const uint16_t addr_type,
    struct SwiftNetHashMap* const packets_sending,
    struct SwiftNetMemoryAllocator* const packets_sending_messages_memory_allocator,
    struct SwiftNetHashMap* const pending_messages,
    struct SwiftNetMemoryAllocator* const pending_messages_memory_allocator,
    struct SwiftNetHashMap* const packets_completed_history,
    struct SwiftNetMemoryAllocator* const packets_completed_history_memory_allocator,
    const enum ConnectionType connection_type,
    struct PacketQueue* const packet_queue,
    struct PacketCallbackQueue* const packet_callback_queue,
    void* const connection,
    const _Atomic bool* const closing,
    const uint8_t prepend_size,
    pthread_mutex_t* const process_packets_mtx,
    pthread_cond_t* const process_packets_cond,
    pthread_mutex_t* const execute_callback_mtx,
    pthread_cond_t* const execute_callback_cond,
    _Atomic bool* const processing_packets
) {
    uint8_t idle_stage;
    struct PacketQueueNode* node;
    uint8_t* packet_buffer;
    uint8_t* packet_data;
    struct ip ip_header;
    struct SwiftNetPacketInfo packet_info;
    uint32_t checksum_received;
    struct SwiftNetClientAddrData sender;
    uint32_t mtu;
    uint32_t chunk_data_size;
    struct SwiftNetPendingMessage* pending_message;


    idle_stage = 0;

process_packet:
    if (atomic_load(closing) == true) {
        goto exit;
    }

    node = wait_for_next_packet(packet_queue);
    if(node == NULL) {
        switch (idle_stage) {
            case 0: usleep(1000); break;
            case 1: usleep(2000); break;
            case 2: usleep(5000); break;
            case 3: {
                atomic_store_explicit(processing_packets, false, memory_order_release);

                pthread_mutex_lock(process_packets_mtx);

                pthread_cond_wait(process_packets_cond, process_packets_mtx);

                pthread_mutex_unlock(process_packets_mtx);

                atomic_store_explicit(processing_packets, true, memory_order_release);

                idle_stage = 0;

                goto process_packet;
            }
        }

        idle_stage++;

        goto process_packet;
    }

    idle_stage = 0;

    packet_buffer = node->data;
    if(unlikely(packet_buffer == NULL)) {
        goto next_packet;
    }

    packet_data = &packet_buffer[prepend_size + PACKET_HEADER_SIZE];

    memcpy(&ip_header, packet_buffer + prepend_size, sizeof(ip_header));

    memcpy(&packet_info, packet_buffer + prepend_size + sizeof(ip_header), sizeof(packet_info));

    // Check if the packet is meant to be for this server
    if(packet_info.port_info.destination_port != source_port) {
        allocator_free(&packet_buffer_memory_allocator, packet_buffer);

        goto next_packet;
    }

    checksum_received = packet_info.checksum;

    memset(packet_buffer + prepend_size + sizeof(struct ip) + offsetof(struct SwiftNetPacketInfo, checksum), 0x00, SIZEOF_FIELD(struct SwiftNetPacketInfo, checksum));

    memcpy(packet_buffer + prepend_size + offsetof(struct ip, ip_len), (void*)&node->data_read, SIZEOF_FIELD(struct ip, ip_len));

    if(memcmp(&ip_header.ip_src, &ip_header.ip_dst, sizeof(struct in_addr)) != 0 && is_private_ip(ip_header.ip_src) == false && is_private_ip(ip_header.ip_dst)) { 
        if(ip_header.ip_sum != 0 && packet_corrupted(checksum_received, node->data_read, packet_buffer) == true) {
            #ifdef SWIFT_NET_DEBUG
                if (check_debug_flag(SWIFTNET_DEBUG_PACKETS_RECEIVING)) {
                    send_debug_message("Received corrupted packet: {\"source_ip_address\": \"%s\", \"source_port\": %d, \"packet_id\": %d, \"received_checsum\": %d, \"real_checksum\": %d}\n", inet_ntoa(ip_header.ip_src), packet_info.port_info.source_port, ip_header.ip_id, checksum_received, crc32(packet_buffer, node->data_read));
                }
            #endif

            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            goto next_packet;
        }
    }

    #ifdef SWIFT_NET_DEBUG
        if (check_debug_flag(SWIFTNET_DEBUG_PACKETS_RECEIVING)) {
            send_debug_message("Received packet: {\"source_ip_address\": \"%s\", \"source_port\": %d, \"packet_id\": %d, \"packet_type\": %d, \"packet_length\": %d, \"chunk_index\": %d, \"connection_type\": %d, \"checksum_received\": %d, \"real_checksum\": %d}\n", inet_ntoa(ip_header.ip_src), packet_info.port_info.source_port, ip_header.ip_id, packet_info.packet_type, packet_info.packet_length, packet_info.chunk_index, connection_type, checksum_received, crc32(node->data, node->data_read));
        }
    #endif

    switch(packet_info.packet_type) {
        case REQUEST_INFORMATION:
        {
            struct ip send_server_info_ip_header;
            struct SwiftNetPacketInfo packet_info_new;
            struct SwiftNetServerInformation server_info;


            send_server_info_ip_header = construct_ip_header(ip_header.ip_src, PACKET_HEADER_SIZE, rand());

            packet_info_new = construct_packet_info(
                sizeof(struct SwiftNetServerInformation),
                REQUEST_INFORMATION,
                1,
                0,
                (struct SwiftNetPortInfo){
                    .source_port = source_port,
                    .destination_port = packet_info.port_info.source_port
                }
            );

            server_info = (struct SwiftNetServerInformation){
                .maximum_transmission_unit = maximum_transmission_unit
            };

            HANDLE_PACKET_CONSTRUCTION(&send_server_info_ip_header, &packet_info_new, addr_type, &eth_hdr, prepend_size + PACKET_HEADER_SIZE + sizeof(server_info), buffer)

            memcpy(buffer + prepend_size + PACKET_HEADER_SIZE, &server_info, sizeof(server_info));

            HANDLE_CHECKSUM(buffer, sizeof(buffer), prepend_size)
            
            SWIFTNET_PCAP_SEND_SAFE(pcap, buffer, sizeof(buffer));

            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            goto next_packet;
        }
        case SEND_LOST_PACKETS_REQUEST:
        {
            uint32_t case_mtu;
            struct SwiftNetPendingMessage* case_pending_message;
            bool packet_already_completed;
            struct ip send_packet_ip_header;
            struct SwiftNetPacketInfo send_packet_info;
            struct ip send_lost_packets_ip_header;
            struct SwiftNetPacketInfo packet_info_new;
            uint16_t header_size;
            uint32_t lost_chunk_indexes;
            uint32_t lost_indexes_size;
            uint32_t packet_length;
            uint16_t packet_length_net_order;


            case_mtu = MIN(packet_info.maximum_transmission_unit, maximum_transmission_unit);

            case_pending_message = get_pending_message(pending_messages, connection_type, ip_header.ip_id, packet_info.port_info.source_port);
            if(case_pending_message == NULL) {
                packet_already_completed = check_packet_already_completed(ip_header.ip_id, packet_info.port_info.source_port, packets_completed_history);
                if(likely(packet_already_completed == true)) {
                    send_packet_ip_header = construct_ip_header(ip_header.ip_src, PACKET_HEADER_SIZE, ip_header.ip_id);

                    send_packet_info = construct_packet_info(
                        0x00,
                        SUCCESSFULLY_RECEIVED_PACKET,
                        1,
                        0,
                        (struct SwiftNetPortInfo){
                            .destination_port = packet_info.port_info.source_port,
                            .source_port = packet_info.port_info.destination_port
                        }
                    );

                    HANDLE_PACKET_CONSTRUCTION(&send_packet_ip_header, &send_packet_info, addr_type, &eth_hdr, prepend_size + PACKET_HEADER_SIZE, buffer)

                    HANDLE_CHECKSUM(buffer, sizeof(buffer), prepend_size)

                    SWIFTNET_PCAP_SEND_SAFE(pcap, buffer, sizeof(buffer));

                    allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                    goto next_packet;
                }

                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                goto next_packet;
            }

            case_pending_message->sending_lost_packets = true;

            send_lost_packets_ip_header = construct_ip_header(ip_header.ip_src, 0, ip_header.ip_id);

            packet_info_new = construct_packet_info(
                0,
                SEND_LOST_PACKETS_RESPONSE,
                1,
                0,
                (struct SwiftNetPortInfo){
                    .destination_port = packet_info.port_info.source_port,
                    .source_port = packet_info.port_info.destination_port
                }
            );

            header_size = PACKET_HEADER_SIZE + prepend_size;

            HANDLE_PACKET_CONSTRUCTION(&send_lost_packets_ip_header, &packet_info_new, addr_type, &eth_hdr, case_mtu + prepend_size, buffer)

            lost_chunk_indexes = return_lost_chunk_indexes(case_pending_message->chunks_received, case_pending_message->packet_info.chunk_amount, case_mtu - PACKET_HEADER_SIZE, (uint32_t*)(buffer + header_size));

            lost_indexes_size = lost_chunk_indexes * sizeof(uint32_t);
            packet_length = PACKET_HEADER_SIZE + (lost_chunk_indexes * sizeof(uint32_t));

            packet_length_net_order = htons((uint16_t)packet_length);

            memcpy(buffer + prepend_size + offsetof(struct ip, ip_len), &packet_length_net_order, SIZEOF_FIELD(struct ip, ip_len));
            memcpy(buffer + prepend_size + sizeof(struct ip) + offsetof(struct SwiftNetPacketInfo, packet_length), &lost_indexes_size, sizeof(lost_indexes_size));

            HANDLE_CHECKSUM(buffer, packet_length + prepend_size, prepend_size);

            SWIFTNET_PCAP_SEND_SAFE(pcap, buffer, packet_length + prepend_size);

            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            goto next_packet;
        }
        case SEND_LOST_PACKETS_RESPONSE:
        {
            struct SwiftNetPacketSending* target_packet_sending;
            uint32_t packets_lost;


            target_packet_sending = get_packet_sending(packets_sending, ip_header.ip_id);

            if(unlikely(target_packet_sending == NULL)) {
                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                goto next_packet;
            }

            LOCK_ATOMIC_DATA_TYPE(&target_packet_sending->locked);

            if(target_packet_sending->lost_chunks == NULL) {
                target_packet_sending->lost_chunks = malloc(maximum_transmission_unit - PACKET_HEADER_SIZE);
            }

            packets_lost = (packet_info.packet_length) / sizeof(uint32_t);

            memcpy((void*)target_packet_sending->lost_chunks, packet_data, packet_info.packet_length);

            target_packet_sending->lost_chunks_size = packet_info.packet_length / 4;

            atomic_store_explicit(&target_packet_sending->updated, UPDATED_LOST_CHUNKS, memory_order_release);

            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            UNLOCK_ATOMIC_DATA_TYPE(&target_packet_sending->locked);

            goto next_packet;
        }
        case SUCCESSFULLY_RECEIVED_PACKET:
        {
            struct SwiftNetPacketSending* target_packet_sending;


            target_packet_sending = get_packet_sending(packets_sending, ip_header.ip_id);

            if(unlikely(target_packet_sending == NULL)) {
                allocator_free(&packet_buffer_memory_allocator, packet_buffer);

                goto next_packet;
            }

            atomic_store_explicit(&target_packet_sending->updated, SUCCESSFULLY_RECEIVED, memory_order_release);

            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            goto next_packet;
        }
        case PACKET_DELAY_UPDATE:
        {
            enum PacketDelayUpdateStatus* status;
            struct SwiftNetPacketSending* target_packet_sending;
            uint32_t current_delay;


            status = (enum PacketDelayUpdateStatus*)packet_data;

            target_packet_sending = get_packet_sending(packets_sending, ip_header.ip_id);

            current_delay = atomic_load_explicit(&target_packet_sending->current_send_delay, memory_order_acquire);

            if (*status == INCREASE_DELAY) {
                current_delay = (current_delay / 6) * 7;
            } else {
                current_delay = (current_delay / 6) * 5;
            }

            atomic_store_explicit(&target_packet_sending->current_send_delay, current_delay, memory_order_release);

            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            goto next_packet;
        }
        default:
            break;
    }

    if (check_packet_already_completed(ip_header.ip_id, packet_info.port_info.source_port, packets_completed_history)) {
        allocator_free(&packet_buffer_memory_allocator, packet_buffer);
        goto next_packet;
    }

    sender = (struct SwiftNetClientAddrData){
        .maximum_transmission_unit = packet_info.maximum_transmission_unit,
        .port = packet_info.port_info.source_port,
    };

    if (addr_type == DLT_EN10MB) {
        memcpy(&sender.mac_address, eth_hdr.ether_shost, sizeof(sender.mac_address));
    }

    mtu = MIN(packet_info.maximum_transmission_unit, maximum_transmission_unit);
    chunk_data_size = mtu - PACKET_HEADER_SIZE;

    pending_message = get_pending_message(pending_messages, connection_type, ip_header.ip_id, packet_info.port_info.source_port);

    if(pending_message == NULL) {
        if(packet_info.packet_length > chunk_data_size) {
            struct SwiftNetPendingMessage* new_pending_message;


            new_pending_message = create_new_pending_message(pending_messages, pending_messages_memory_allocator, &packet_info, connection_type, ip_header.ip_id, packet_info.port_info.source_port);

            new_pending_message->chunks_received_number = 1;

            chunk_received(new_pending_message->chunks_received, packet_info.chunk_index);
                
            memcpy(new_pending_message->packet_data_start, packet_data, chunk_data_size);

            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            goto next_packet;
        } else {
            packet_completed(ip_header.ip_id, packet_info.port_info.source_port, packets_completed_history, packets_completed_history_memory_allocator);

            if(connection_type == CONNECTION_TYPE_SERVER) {
                struct SwiftNetServerPacketData* new_packet_data;


                new_packet_data = allocator_allocate(&server_packet_data_memory_allocator);
                new_packet_data->data = packet_data;
                new_packet_data->current_pointer = packet_data;
                new_packet_data->internal_pending_message = NULL;
                new_packet_data->metadata = (struct SwiftNetPacketServerMetadata){
                    .port_info = packet_info.port_info,
                    .sender = sender,
                    .data_length = packet_info.packet_length,
                    .packet_id = ip_header.ip_id
                    #ifdef SWIFT_NET_REQUESTS
                        , .expecting_response = packet_info.packet_type == REQUEST
                    #endif
                };

                #ifdef SWIFT_NET_REQUESTS
                if (packet_info.packet_type == RESPONSE) {
                    handle_request_response(ip_header.ip_id, NULL, new_packet_data, pending_messages, pending_messages_memory_allocator, connection_type, loopback, packet_info.port_info.source_port);
                } else {
                    pass_callback_execution(new_packet_data, packet_callback_queue, NULL, ip_header.ip_id, execute_callback_mtx, execute_callback_cond);
                }
                #else
                    pass_callback_execution(new_packet_data, packet_callback_queue, NULL, ip_header.ip_id, execute_callback_mtx, execute_callback_cond);
                #endif
            } else {
                struct SwiftNetClientPacketData* new_packet_data;


                new_packet_data = allocator_allocate(&client_packet_data_memory_allocator);
                new_packet_data->data = packet_data;
                new_packet_data->current_pointer = packet_data;
                new_packet_data->internal_pending_message = NULL;
                new_packet_data->metadata = (struct SwiftNetPacketClientMetadata){
                    .port_info = packet_info.port_info,
                    .data_length = packet_info.packet_length,
                    .packet_id = ip_header.ip_id
                    #ifdef SWIFT_NET_REQUESTS
                        , .expecting_response = packet_info.packet_type == REQUEST
                    #endif
                };

                #ifdef SWIFT_NET_REQUESTS
                if (packet_info.packet_type == RESPONSE) {
                    handle_request_response(ip_header.ip_id, NULL, new_packet_data, pending_messages, pending_messages_memory_allocator, connection_type, loopback, packet_info.port_info.source_port);
                } else {
                    pass_callback_execution(new_packet_data, packet_callback_queue, NULL, ip_header.ip_id, execute_callback_mtx, execute_callback_cond);
                }
                #else
                    pass_callback_execution(new_packet_data, packet_callback_queue, NULL, ip_header.ip_id, execute_callback_mtx, execute_callback_cond);
                #endif
            }

            goto next_packet;
        }
    } else {
        uint32_t bytes_to_write;

        if (chunk_already_received(pending_message->chunks_received, packet_info.chunk_index)) {
            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            goto next_packet;
        }

        bytes_to_write = (packet_info.chunk_index + 1) >= packet_info.chunk_amount ? packet_info.packet_length % chunk_data_size : chunk_data_size;

        if(pending_message->chunks_received_number + 1 == packet_info.chunk_amount) {

            pending_message->chunks_received_number++;

            // Completed the packet
            memcpy(pending_message->packet_data_start + (chunk_data_size * packet_info.chunk_index), packet_data, bytes_to_write);

            chunk_received(pending_message->chunks_received, packet_info.chunk_index);

            #ifdef SWIFT_NET_DEBUG
            {
                uint32_t lost_chunks_buffer[chunk_data_size];
                uint32_t lost_chunks_num;


                lost_chunks_num = return_lost_chunk_indexes(pending_message->chunks_received, packet_info.chunk_amount, chunk_data_size, (uint32_t*)lost_chunks_buffer);

                if (lost_chunks_num != 0) {
                    PRINT_ERROR("Packet marked as completed, but %d chunks are missing", lost_chunks_num);

                    for (uint32_t i = 0; i < lost_chunks_num; i++) {
                        printf("chunk index missing: %d\n", *(lost_chunks_buffer + i));  
                    }
                }
            }
            #endif

            packet_completed(ip_header.ip_id, packet_info.port_info.source_port, packets_completed_history, packets_completed_history_memory_allocator);

            if(connection_type == CONNECTION_TYPE_SERVER) {
                uint8_t* ptr;
                struct SwiftNetServerPacketData* server_packet_data;


                ptr = pending_message->packet_data_start;

                server_packet_data = allocator_allocate(&server_packet_data_memory_allocator);
                server_packet_data->data = ptr;
                server_packet_data->current_pointer = ptr;
                server_packet_data->internal_pending_message = pending_message;
                server_packet_data->metadata = (struct SwiftNetPacketServerMetadata){
                    .port_info = packet_info.port_info,
                    .sender = sender,
                    .data_length = packet_info.packet_length,
                    .packet_id = ip_header.ip_id
                    #ifdef SWIFT_NET_REQUESTS
                        , .expecting_response = packet_info.packet_type == REQUEST
                    #endif
                };

                #ifdef SWIFT_NET_REQUESTS
                if (packet_info.packet_type == RESPONSE) {
                    handle_request_response(ip_header.ip_id, pending_message, server_packet_data, pending_messages, pending_messages_memory_allocator, connection_type, loopback, packet_info.port_info.source_port);
                } else {
                    pass_callback_execution(server_packet_data, packet_callback_queue, pending_message, ip_header.ip_id, execute_callback_mtx, execute_callback_cond);
                }
                #else
                    pass_callback_execution(server_packet_data, packet_callback_queue, pending_message, ip_header.ip_id, execute_callback_mtx, execute_callback_cond);
                #endif
            } else {
                uint8_t* ptr;
                struct SwiftNetClientPacketData* client_packet_data;


                ptr = pending_message->packet_data_start;

                client_packet_data = allocator_allocate(&client_packet_data_memory_allocator);
                client_packet_data->data = ptr;
                client_packet_data->current_pointer = ptr;
                client_packet_data->internal_pending_message = pending_message;
                client_packet_data->metadata = (struct SwiftNetPacketClientMetadata){
                    .port_info = packet_info.port_info,
                    .data_length = packet_info.packet_length,
                    .packet_id = ip_header.ip_id
                    #ifdef SWIFT_NET_REQUESTS
                        , .expecting_response = packet_info.packet_type == REQUEST
                    #endif
                };

                #ifdef SWIFT_NET_REQUESTS
                if (packet_info.packet_type == RESPONSE) {
                    handle_request_response(ip_header.ip_id, pending_message, client_packet_data, pending_messages, pending_messages_memory_allocator, connection_type, loopback, packet_info.port_info.source_port);
                } else {
                    pass_callback_execution(client_packet_data, packet_callback_queue, pending_message, ip_header.ip_id, execute_callback_mtx, execute_callback_cond);
                }
                #else
                    pass_callback_execution(client_packet_data, packet_callback_queue, pending_message, ip_header.ip_id, execute_callback_mtx, execute_callback_cond);
                #endif
            }

            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            goto next_packet;
        } else {
            uint32_t new_packets;
            uint32_t new_packets_validated;
            float ratio;


            new_packets = packet_info.chunk_index - pending_message->last_index_checked;
            new_packets_validated = pending_message->chunks_received_number - pending_message->last_chunks_received_number;

            if (new_packets > 50) {
                ratio = (float)new_packets_validated / (float)new_packets;
                if (ratio > 0.95) {
                    signal_delay_change(LOWER_DELAY, &ip_header, source_port, packet_info.port_info.source_port, addr_type, prepend_size, pcap, &eth_hdr);
                } else {
                    signal_delay_change(INCREASE_DELAY, &ip_header, source_port, packet_info.port_info.source_port, addr_type, prepend_size, pcap, &eth_hdr);
                }

                pending_message->last_chunks_received_number = pending_message->chunks_received_number;
                pending_message->last_index_checked = packet_info.chunk_index;
            }

            memcpy(pending_message->packet_data_start + (chunk_data_size * packet_info.chunk_index), packet_data, bytes_to_write);

            chunk_received(pending_message->chunks_received, packet_info.chunk_index);

            pending_message->chunks_received_number++;

            allocator_free(&packet_buffer_memory_allocator, packet_buffer);

            goto next_packet;
        }
    }

    goto next_packet;

next_packet:
    allocator_free(&packet_queue_node_memory_allocator, (void*)node);

    goto process_packet;
exit:
    return;
}

void* swiftnet_server_process_packets(void* const void_server) {
    struct SwiftNetServer* server;


    server = void_server;

    swiftnet_process_packets((void*)&server->packet_handler, server->pcap, server->eth_header, server->server_port, server->loopback, server->addr_type, &server->packets_sending, &server->packets_sending_memory_allocator, &server->pending_messages, &server->pending_messages_memory_allocator, &server->packets_completed, &server->packets_completed_memory_allocator, CONNECTION_TYPE_SERVER, &server->packet_queue, &server->packet_callback_queue, server, &server->closing, server->prepend_size, &server->process_packets_mtx, &server->process_packets_cond, &server->execute_callback_mtx, &server->execute_callback_cond, &server->processing_packets);

    return NULL;
}

void* swiftnet_client_process_packets(void* const void_client) {
    struct SwiftNetClientConnection* client;


    client = (struct SwiftNetClientConnection*)void_client;

    swiftnet_process_packets((void*)&client->packet_handler, client->pcap, client->eth_header, client->port_info.source_port, client->loopback, client->addr_type, &client->packets_sending, &client->packets_sending_memory_allocator, &client->pending_messages, &client->pending_messages_memory_allocator, &client->packets_completed, &client->packets_completed_memory_allocator, CONNECTION_TYPE_CLIENT, &client->packet_queue, &client->packet_callback_queue, client, &client->closing, client->prepend_size, &client->process_packets_mtx, &client->process_packets_cond, &client->execute_callback_mtx, &client->execute_callback_cond, &client->processing_packets);

    return NULL;
}
