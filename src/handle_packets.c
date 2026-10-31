#include "internal/networking.h"
#include "swift_net.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "internal/internal.h"
#include <stddef.h>

#if defined (__APPLE__) || defined(__linux__)
#include <stdlib.h>
#endif

static inline void insert_queue_node(
    struct SwiftNetPacketQueueNode* const new_node,
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

static inline struct SwiftNetPacketQueueNode* construct_node(const uint32_t data_read, void* const data, const uint32_t sender_address) {
    struct SwiftNetPacketQueueNode* node;


    node = allocator_allocate(&packet_queue_node_memory_allocator);
    if (unlikely(node == NULL)) {
        return NULL;
    }

    *node = (struct SwiftNetPacketQueueNode){
        .data = data,
        .data_read = data_read,
        .sender_address = (struct in_addr){.s_addr = sender_address},
        .next = NULL
    };

    return node;
}

static inline bool valid_chunk_metadata(const struct SwiftNetNetworkData* restrict const network_data, const struct ReceiverPacketData* const restrict packet_data) {
    struct SwiftNetChunkMetadata* restrict chunk_metadata;

    chunk_metadata = (struct SwiftNetChunkMetadata*)(packet_data->data + GET_PREPEND_SIZE(network_data) + sizeof(struct SwiftNetIp));

    if(chunk_metadata->packet_type <= PACKET_TYPE_END) return true;

    return false;
}

static inline bool valid_ip_header(const struct SwiftNetNetworkData* restrict const network_data, const struct ReceiverPacketData* const restrict packet_data) {
    struct SwiftNetIp* restrict ip_header;
    bool valid_const_fields;


    ip_header = (struct SwiftNetIp*)(packet_data->data + GET_PREPEND_SIZE(network_data));

    valid_const_fields = (
        ip_header->ip_hl == 5 &&
        ip_header->ip_v == 4 &&
        ip_header->ip_tos == 0 &&
        ip_header->ip_off == htons(0) &&
        ip_header->ip_ttl == 64
    );

    return valid_const_fields && ip_checksum((uint8_t*)ip_header) == 0;
}

static inline bool valid_packet(const struct SwiftNetNetworkData* restrict const network_data, const struct ReceiverPacketData* const restrict packet_data) {
    if(!valid_ip_header(network_data, packet_data)) return false;
    if(!valid_chunk_metadata(network_data, packet_data)) return false;

    return true;
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
    uint8_t* packet_buffer;


    addr_type = GET_ADDR_TYPE(network_data);

    if (!valid_packet(network_data, &packet_data)) {
        goto exit;   
    }

    if (unlikely(packet_data.data_len == 0)) {
        goto exit;
    }

    packet_buffer = allocator_allocate(&packet_buffer_memory_allocator);
    if (unlikely(packet_buffer == NULL)) {
        goto exit;
    }

    memcpy(packet_buffer, packet_data.data, packet_data.data_len);


    sender_address = 0;

    if (addr_type != 0) {
        if (ntohs(((struct SwiftNetEtherHeader *)packet_buffer)->ether_type) == ETH_TYPE_IP) {
            sender_address = ((struct SwiftNetIp *)(packet_buffer + sizeof(struct SwiftNetEtherHeader)))->ip_src.s_addr;
            
        } else {
            allocator_free(&packet_buffer_memory_allocator, packet_buffer);
            return;
        }
    }


    insert_queue_node(construct_node(packet_data.data_len, packet_buffer, sender_address), packet_queue);


    if (atomic_load_explicit(processing_packets, memory_order_acquire) != true) {
        pthread_mutex_lock(process_packets_mtx);

        pthread_cond_signal(process_packets_cond);

        pthread_mutex_unlock(process_packets_mtx);
    }

exit:
    #ifdef SWIFT_NET_BACKEND_DPDK
        rte_pktmbuf_free(packet_data.dpdk_buf);
    #endif

    return;
}

static void handle_client_init(struct SwiftNetClientConnection* const client_connection, struct ReceiverPacketData* const restrict packet_data) {
    struct SwiftNetChunkMetadata* restrict chunk_metadata;
    struct SwiftNetServerInformation* restrict server_information;

    struct SwiftNetNetworkData* network_data;

    uint8_t* buffer;
    uint32_t bytes_received;

    uint8_t prepend_size;
    uint16_t addr_type;

    uint32_t expecting_size;

    prepend_size = GET_PREPEND_SIZE(&client_connection->network_data);
    addr_type = GET_ADDR_TYPE(&client_connection->network_data);
    buffer = (uint8_t*)packet_data->data;
    bytes_received = packet_data->data_len;
    network_data = &client_connection->network_data;

    expecting_size = PACKET_HEADER_SIZE + sizeof(struct SwiftNetServerInformation) + prepend_size;


    if (atomic_load_explicit(&client_connection->closing, memory_order_acquire) == true) {
        return;
    }


    if(bytes_received != expecting_size) {
        #ifndef SWIFT_NET_DISABLE_DEBUGGING
            if (check_debug_flag(SWIFTNET_DEBUG_INITIALIZATION)) {
                send_debug_message("Invalid packet received from server. Expected server information: {\"bytes_received\": %u, \"expected_bytes\": %u}\n", bytes_received, expecting_size);
            }
        #endif

        return;
    }

    if (addr_type != 0) {
        memcpy(client_connection->eth_header.ether_dhost, ((struct SwiftNetEtherHeader*)buffer)->ether_shost, sizeof(client_connection->eth_header.ether_dhost));
    }


    chunk_metadata = (struct SwiftNetChunkMetadata*)(CHUNK_METADATA_LOCATION(buffer, network_data));
    server_information = (struct SwiftNetServerInformation*)(DATA_LOCATION(buffer, network_data, false));

    if(chunk_metadata->port_info.destination_port != client_connection->port_info.source_port || chunk_metadata->port_info.source_port != client_connection->port_info.destination_port) {
        #ifndef SWIFT_NET_DISABLE_DEBUGGING
            if (check_debug_flag(SWIFTNET_DEBUG_INITIALIZATION)) {
                send_debug_message("Port info does not match: {\"destination_port\": %d, \"source_port\": %d, \"source_ip_address\": \"%s\"}\n", chunk_metadata->port_info.destination_port, chunk_metadata->port_info.source_port, inet_ntoa(((struct SwiftNetIp*)(buffer + prepend_size))->ip_src));
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

        if (unlikely(client_connection == NULL)) {
            printf("no cc\n");
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

        printf("dest port: %d\n", port_info->destination_port);

        server = hashmap_get(&port_info->destination_port, sizeof(uint16_t), &listener->servers);

        UNLOCK_ATOMIC_DATA_TYPE(&listener->servers.atomic_lock);

        if (unlikely(server == NULL)) {
            return 0;
        }

        swiftnet_handle_packets(&server->packet_queue, &server->process_packets_mtx, &server->process_packets_cond, &server->processing_packets, &server->network_data, *packet_data);

        return 1;
    }
}

#ifdef SWIFT_NET_BACKEND_PCAP
static void pcap_packet_handle(uint8_t* const user, const struct pcap_pkthdr* restrict const hdr, const uint8_t* const packet) {
    struct Listener* listener;
    struct SwiftNetPortInfo* restrict port_info;

    listener = (struct Listener*)user;

    port_info = (struct SwiftNetPortInfo*)(packet + PACKET_PREPEND_SIZE(listener->addr_type) + sizeof(struct SwiftNetIp) + offsetof(struct SwiftNetChunkMetadata, port_info));

    struct ReceiverPacketData packet_data = (struct ReceiverPacketData){.data = packet, .data_len = hdr->caplen};

    if(handle_correct_receiver(CONNECTION_TYPE_SERVER, listener, port_info, &packet_data) == 0) handle_correct_receiver(CONNECTION_TYPE_CLIENT, listener, port_info, &packet_data);
}
#elif defined(SWIFT_NET_BACKEND_DPDK)
static void dpdk_packet_handle(struct Listener* const listener, struct rte_mbuf* const restrict dpdk_buf, uint8_t* restrict const packet) {
    struct SwiftNetPortInfo* restrict const port_info = (struct SwiftNetPortInfo*)(packet + PACKET_PREPEND_SIZE(listener->addr_type) + sizeof(struct SwiftNetIp) + offsetof(struct SwiftNetChunkMetadata, port_info));
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

