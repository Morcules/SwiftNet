#include "internal/networking.h"
#include "swift_net.h"
#include <arpa/inet.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include "internal/internal.h"
#include <stddef.h>

static inline void insert_queue_node(
    struct SwiftNetPacketQueueNode* restrict const new_node,
    struct SwiftNetPacketQueue* const packet_queue
) {
    if(unlikely(new_node == NULL)) {
        return;
    }

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

static inline struct SwiftNetPacketQueueNode* construct_node(const uint32_t data_read, void* restrict const data, const uint32_t sender_address) {
    struct SwiftNetPacketQueueNode* restrict node;


    node = allocator_allocate(&packet_queue_node_memory_allocator);
    if (unlikely(node == NULL)) {
        return NULL;
    }

    goto node_assign_values;


node_assign_values:
    *node = (struct SwiftNetPacketQueueNode){
        .data = data,
        .data_read = data_read,
        .sender_address = (struct in_addr){.s_addr = sender_address},
        .next = NULL
    };

    goto exit;


exit:
    return node;
}

static inline void swiftnet_handle_packets(
	struct SwiftNetPacketQueue* const packet_queue,
    pthread_mutex_t* const process_packets_mtx,
    pthread_cond_t* const process_packets_cond,
    _Atomic bool *const processing_packets,
    const struct SwiftNetNetworkData* const restrict network_data,
    const struct ReceiverPacketData packet_data
) {
    uint16_t addr_type;

    uint32_t sender_address;
    uint8_t* restrict packet_buffer;


    addr_type = GET_ADDR_TYPE(network_data);

    if (unlikely(packet_data.data_len == 0)) {
        goto exit;
    }

    packet_buffer = allocator_allocate(&packet_buffer_memory_allocator);
    if (unlikely(packet_buffer == NULL)) {
        goto exit;
    }

    memcpy(packet_buffer, packet_data.data, packet_data.data_len);

    goto get_sender_addr;


get_sender_addr:
    sender_address = 0;

    if (addr_type != 0) {
        if (ntohs(((struct ether_header *)packet_buffer)->ether_type) == ETHERTYPE_IP) {
            sender_address = ((struct ip *)(packet_buffer + sizeof(struct ether_header)))->ip_src.s_addr;
            
        } else {
            allocator_free(&packet_buffer_memory_allocator, packet_buffer);
            return;
        }
    }

    goto insert_node;


insert_node:
    insert_queue_node(construct_node(packet_data.data_len, packet_buffer, sender_address), packet_queue);

    goto unlock_processing_thread;


unlock_processing_thread:
    if (atomic_load_explicit(processing_packets, memory_order_acquire) != true) {
        pthread_mutex_lock(process_packets_mtx);

        pthread_cond_signal(process_packets_cond);

        pthread_mutex_unlock(process_packets_mtx);
    }

    goto exit;


exit:
    #ifdef SWIFT_NET_BACKEND_DPDK
        rte_pktmbuf_free(packet_data.dpdk_buf);
    #endif

    return;
}

static void handle_client_init(struct SwiftNetClientConnection* const client_connection, struct ReceiverPacketData* const restrict packet_data) {
    struct SwiftNetChunkMetadata* restrict chunk_metadata;
    struct SwiftNetServerInformation* restrict server_information;

    uint8_t* buffer;
    uint32_t bytes_received;

    uint8_t prepend_size;
    uint16_t addr_type;

    prepend_size = GET_PREPEND_SIZE(&client_connection->network_data);
    addr_type = GET_ADDR_TYPE(&client_connection->network_data);
    buffer = (uint8_t*)packet_data->data;
    bytes_received = packet_data->data_len;

    goto check_closing;


check_closing:
    if (atomic_load_explicit(&client_connection->closing, memory_order_acquire) == true) {
        return;
    }

    goto validate_packet_size;


validate_packet_size:
    if(bytes_received != PACKET_HEADER_SIZE + sizeof(struct SwiftNetServerInformation) + prepend_size) {
        #ifndef SWIFT_NET_DISABLE_DEBUGGING
            if (check_debug_flag(SWIFTNET_DEBUG_INITIALIZATION)) {
                send_debug_message("Invalid packet received from server. Expected server information: {\"bytes_received\": %u, \"expected_bytes\": %lu}\n", bytes_received, PACKET_HEADER_SIZE + sizeof(struct SwiftNetServerInformation) + prepend_size);
            }
        #endif

        return;
    }

    goto handle_mac_address;

handle_mac_address:
    if (addr_type != 0) {
        memcpy(client_connection->eth_header.ether_dhost, ((struct ether_header*)buffer)->ether_shost, sizeof(client_connection->eth_header.ether_dhost));
    }

    goto validate_target;


validate_target:
    chunk_metadata = (struct SwiftNetChunkMetadata*)(buffer + prepend_size + sizeof(struct ip));
    server_information = (struct SwiftNetServerInformation*)(buffer + prepend_size+ sizeof(struct ip) + sizeof(struct SwiftNetChunkMetadata));

    if(chunk_metadata->port_info.destination_port != client_connection->port_info.source_port || chunk_metadata->port_info.source_port != client_connection->port_info.destination_port) {
        #ifndef SWIFT_NET_DISABLE_DEBUGGING
            if (check_debug_flag(SWIFTNET_DEBUG_INITIALIZATION)) {
                send_debug_message("Port info does not match: {\"destination_port\": %d, \"source_port\": %d, \"source_ip_address\": \"%s\"}\n", chunk_metadata->port_info.destination_port, chunk_metadata->port_info.source_port, inet_ntoa(((struct ip*)(buffer + prepend_size))->ip_src));
            }
        #endif

        goto exit;
    }

    if(chunk_metadata->packet_type != REQUEST_INFORMATION) {
        #ifndef SWIFT_NET_DISABLE_DEBUGGING
            if (check_debug_flag(SWIFTNET_DEBUG_INITIALIZATION)) {
                send_debug_message("Invalid packet type: {\"packet_type\": %d}\n", chunk_metadata->packet_type);
            }
        #endif

        goto exit;
    }

    goto finalize_initialization;


finalize_initialization:
        
    client_connection->maximum_transmission_unit = server_information->maximum_transmission_unit;

    atomic_store_explicit(&client_connection->initialized, true, memory_order_release);

    goto exit;


exit:
    #ifdef SWIFT_NET_BACKEND_DPDK
        rte_pktmbuf_free(packet_data->dpdk_buf);
    #endif

    return;
}

static inline uint8_t handle_correct_receiver(const enum ConnectionType connection_type, struct Listener* const listener, const struct SwiftNetPortInfo* restrict const port_info, struct ReceiverPacketData* const restrict packet_data) {
    if (connection_type == CONNECTION_TYPE_CLIENT) {
        struct SwiftNetClientConnection* client_connection;

        LOCK_ATOMIC_DATA_TYPE(&listener->client_connections.atomic_lock);

        client_connection = hashmap_get(&port_info->destination_port, sizeof(uint16_t), &listener->client_connections);
        UNLOCK_ATOMIC_DATA_TYPE(&listener->client_connections.atomic_lock);

        if (client_connection == NULL) {
            return 0;
        }

        if (atomic_load_explicit(&client_connection->initialized, memory_order_acquire) == false) {
            handle_client_init(client_connection, packet_data);
        } else {
            swiftnet_handle_packets(&client_connection->packet_queue, &client_connection->process_packets_mtx, &client_connection->process_packets_cond, &client_connection->processing_packets, &client_connection->network_data, *packet_data);
        }

        return 1;
    } else {
        struct SwiftNetServer* server;

        LOCK_ATOMIC_DATA_TYPE(&listener->servers.atomic_lock);

        server = hashmap_get(&port_info->destination_port, sizeof(uint16_t), &listener->servers);

        UNLOCK_ATOMIC_DATA_TYPE(&listener->servers.atomic_lock);

        if (server == NULL) {
            return 0;
        }

        swiftnet_handle_packets(&server->packet_queue, &server->process_packets_mtx, &server->process_packets_cond, &server->processing_packets, &server->network_data, *packet_data);

        return 1;
    }
}

#ifdef SWIFT_NET_BACKEND_PCAP
static void pcap_packet_handle(uint8_t* const user, const struct pcap_pkthdr* restrict const hdr, const uint8_t* const packet) {
    struct Listener* const listener = (struct Listener*)user;
    struct SwiftNetPortInfo* restrict const port_info = (struct SwiftNetPortInfo*)(packet + PACKET_PREPEND_SIZE(listener->addr_type) + sizeof(struct ip) + offsetof(struct SwiftNetChunkMetadata, port_info));
    struct ReceiverPacketData packet_data = (struct ReceiverPacketData){.data = packet, .data_len = hdr->caplen};

    if(handle_correct_receiver(CONNECTION_TYPE_CLIENT, listener, port_info, &packet_data) == 0) handle_correct_receiver(CONNECTION_TYPE_SERVER, listener, port_info, &packet_data);
}
#elif defined(SWIFT_NET_BACKEND_DPDK)
static void dpdk_packet_handle(struct Listener* const listener, struct rte_mbuf* const restrict dpdk_buf, uint8_t* restrict const packet) {
    struct SwiftNetPortInfo* restrict const port_info = (struct SwiftNetPortInfo*)(packet + PACKET_PREPEND_SIZE(listener->addr_type) + sizeof(struct ip) + offsetof(struct SwiftNetPacketInfo, port_info));
    struct ReceiverPacketData packet_data = (struct ReceiverPacketData){.data = packet, .data_len = dpdk_buf->data_len, .dpdk_buf = dpdk_buf};

    if(handle_correct_receiver(CONNECTION_TYPE_CLIENT, listener, port_info, &packet_data) == 0) handle_correct_receiver(CONNECTION_TYPE_SERVER, listener, port_info, &packet_data);
}
#endif

#ifdef SWIFT_NET_BACKEND_PCAP 
void* interface_start_listening_pcap(void* listener_void) {
    struct Listener* listener = listener_void;

    SWIFTNET_LOOP_PACKETS(&listener->network_data, listener);
    
    return NULL;
}
#elif defined(SWIFT_NET_BACKEND_DPDK) 
int interface_start_listening_dpdk(void* listener_void) {
    struct Listener* listener = listener_void;

    SWIFTNET_LOOP_PACKETS(&listener->network_data, listener);

    return 0;
}
#endif
