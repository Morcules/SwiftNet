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
    struct PacketQueueNode* const new_node,
    struct PacketQueue* const packet_queue,
    const enum ConnectionType contype

) {
    if(new_node == NULL) {
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

static inline struct PacketQueueNode* construct_node(const uint32_t data_read, void* const data, const uint32_t sender_address) {
    struct PacketQueueNode* const node = allocator_allocate(&packet_queue_node_memory_allocator);
    if (unlikely(node == NULL)) {
        return NULL;
    }

    node->data = data;
    node->data_read = data_read;
    node->sender_address.s_addr = sender_address;
    
    node->next = NULL;

    return node;
}

static inline void swiftnet_handle_packets(
    const uint16_t source_port,
	pthread_t* const process_packets_thread,
	void* connection,
	const enum ConnectionType connection_type,
	struct PacketQueue* const packet_queue,
	const _Atomic bool* closing,
	const bool loopback,
	const uint16_t addr_type,
	const struct pcap_pkthdr* hdr,
	const uint8_t* packet,
    pthread_mutex_t* const process_packets_mtx,
    pthread_cond_t* const process_packets_cond

) {
    uint8_t* const packet_buffer = allocator_allocate(&packet_buffer_memory_allocator);
    if (unlikely(packet_buffer == NULL)) {
        return;
    }

    const uint32_t len = hdr->caplen;
    memcpy(packet_buffer, packet, len);

    if (unlikely(len == 0)) {
        allocator_free(&packet_buffer_memory_allocator, packet_buffer);
        return;
    }

    uint32_t sender_address = 0;

    if (addr_type == DLT_EN10MB) {
        struct ether_header* const eth = (struct ether_header *)packet_buffer;

        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_header = (struct ip *)(packet_buffer + sizeof(struct ether_header));

            sender_address = ip_header->ip_src.s_addr;
            
        } else {
            allocator_free(&packet_buffer_memory_allocator, packet_buffer);
            return;
        }
    }

    struct PacketQueueNode* const node = construct_node(len, packet_buffer, sender_address);

    atomic_thread_fence(memory_order_release);

    pthread_mutex_lock(process_packets_mtx);

    insert_queue_node(node, packet_queue, connection_type);

    pthread_cond_signal(process_packets_cond);

    pthread_mutex_unlock(process_packets_mtx);
}

static void handle_client_init(struct SwiftNetClientConnection* user, const struct pcap_pkthdr* hdr, const uint8_t* buffer) {
    struct SwiftNetClientConnection* const client_connection = (struct SwiftNetClientConnection*)user;

    if (atomic_load_explicit(&client_connection->closing, memory_order_acquire) == true) {
        return;
    }

    const uint32_t bytes_received = hdr->caplen;

    if(bytes_received != PACKET_HEADER_SIZE + sizeof(struct SwiftNetServerInformation) + client_connection->prepend_size) {
        #ifdef SWIFT_NET_DEBUG
            if (check_debug_flag(INITIALIZATION)) {
                send_debug_message("Invalid packet received from server. Expected server information: {\"bytes_received\": %u, \"expected_bytes\": %u}\n", bytes_received, PACKET_HEADER_SIZE + sizeof(struct SwiftNetServerInformation));
            }
        #endif

        return;
    }

    struct ip* const ip_header = (struct ip*)(buffer + client_connection->prepend_size);

    if (client_connection->addr_type == DLT_EN10MB) {
        memcpy(client_connection->eth_header.ether_dhost, ((struct ether_header*)buffer)->ether_shost, sizeof(client_connection->eth_header.ether_dhost));
    }

    struct SwiftNetPacketInfo* const packet_info = (struct SwiftNetPacketInfo*)(buffer + client_connection->prepend_size + sizeof(struct ip));
    struct SwiftNetServerInformation* const server_information = (struct SwiftNetServerInformation*)(buffer + client_connection->prepend_size + sizeof(struct ip) + sizeof(struct SwiftNetPacketInfo));

    if(packet_info->port_info.destination_port != client_connection->port_info.source_port || packet_info->port_info.source_port != client_connection->port_info.destination_port) {
        #ifdef SWIFT_NET_DEBUG
            if (check_debug_flag(INITIALIZATION)) {
                send_debug_message("Port info does not match: {\"destination_port\": %d, \"source_port\": %d, \"source_ip_address\": \"%s\"}\n", packet_info->port_info.destination_port, packet_info->port_info.source_port, inet_ntoa(ip_header->ip_src));
            }
        #endif

        return;
    }

    if(packet_info->packet_type != REQUEST_INFORMATION) {
        #ifdef SWIFT_NET_DEBUG
            if (check_debug_flag(INITIALIZATION)) {
                send_debug_message("Invalid packet type: {\"packet_type\": %d}\n", packet_info->packet_type);
            }
        #endif
        return;
    }
        
    client_connection->maximum_transmission_unit = server_information->maximum_transmission_unit;

    atomic_store_explicit(&client_connection->initialized, true, memory_order_release);
}

static inline void handle_correct_receiver(const enum ConnectionType connection_type, struct Listener* const listener, const struct pcap_pkthdr* const hdr, const uint8_t* const packet, const struct SwiftNetPortInfo* const port_info) {
    if (connection_type == CONNECTION_TYPE_CLIENT) {
        LOCK_ATOMIC_DATA_TYPE(&listener->client_connections.locked);

        for (uint16_t i = 0; i < listener->client_connections.size; i++) {
            struct SwiftNetClientConnection* const client_connection = vector_get(&listener->client_connections, i);
            if (client_connection->port_info.source_port == port_info->destination_port) {
                UNLOCK_ATOMIC_DATA_TYPE(&listener->client_connections.locked);

                if (client_connection->initialized == false) {
                    handle_client_init(client_connection, hdr, packet);
                } else {
                    swiftnet_handle_packets(client_connection->port_info.source_port, &client_connection->process_packets_thread, client_connection, CONNECTION_TYPE_CLIENT, &client_connection->packet_queue, &client_connection->closing, client_connection->loopback, client_connection->addr_type, hdr, packet, &client_connection->process_packets_mtx, &client_connection->process_packets_cond);
                }

                return;
            }
        }

        UNLOCK_ATOMIC_DATA_TYPE(&listener->client_connections.locked);
    } else {
        LOCK_ATOMIC_DATA_TYPE(&listener->servers.locked);

        for (uint16_t i = 0; i < listener->servers.size; i++) {
            struct SwiftNetServer* const server = vector_get(&listener->servers, i);
            if (server->server_port == port_info->destination_port) {
                UNLOCK_ATOMIC_DATA_TYPE(&listener->servers.locked);

                swiftnet_handle_packets(server->server_port, &server->process_packets_thread, server, CONNECTION_TYPE_SERVER, &server->packet_queue, &server->closing, server->loopback, server->addr_type, hdr, packet, &server->process_packets_mtx, &server->process_packets_cond);

                return;
            }
        }

        UNLOCK_ATOMIC_DATA_TYPE(&listener->servers.locked);
    }
}

static void pcap_packet_handle(uint8_t* const user, const struct pcap_pkthdr* const hdr, const uint8_t* const packet) {
    struct Listener* const listener = (struct Listener*)user;

    struct SwiftNetPortInfo* const port_info = (struct SwiftNetPortInfo*)(packet + PACKET_PREPEND_SIZE(listener->addr_type) + sizeof(struct ip) + offsetof(struct SwiftNetPacketInfo, port_info));

    handle_correct_receiver(CONNECTION_TYPE_CLIENT, listener, hdr, packet, port_info);
    handle_correct_receiver(CONNECTION_TYPE_SERVER, listener, hdr, packet, port_info);
}

void* interface_start_listening(void* listener_void) {
    struct Listener* listener = listener_void;

    pcap_loop(listener->pcap, 0, pcap_packet_handle, listener_void);

    return NULL;
}
