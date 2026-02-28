#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "internal/internal.h"
#include "swift_net.h"
#include <fcntl.h>
#include <stddef.h>
#include <sys/time.h>
#include <net/ethernet.h>

struct RequestServerInformationArgs {
    const uint32_t size;
    const struct in_addr server_addr;
    pcap_t* pcap;
    const uint32_t timeout_ms;
    const void* const data;
    struct SwiftNetClientConnection* const connection;
};

void* request_server_information(void* const request_server_information_args_void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    uint32_t start = (uint32_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

    const struct RequestServerInformationArgs* const request_server_information_args = (struct RequestServerInformationArgs*)request_server_information_args_void;

    while (1) {
        struct timeval tv;
        gettimeofday(&tv, NULL);

        uint32_t end = (uint32_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

        if (end > start + request_server_information_args->timeout_ms) {
            break;
        }

        if(atomic_load_explicit(&request_server_information_args->connection->initialized, memory_order_acquire) == true) {
            return NULL;
        }

        #ifdef SWIFT_NET_DEBUG
            if (check_debug_flag(INITIALIZATION)) {
                send_debug_message("Requested server information: {\"server_ip_address\": \"%s\"}\n", inet_ntoa(request_server_information_args->server_addr));
            }
        #endif

        swiftnet_pcap_send(request_server_information_args->pcap, request_server_information_args->data, request_server_information_args->size);

        usleep(250000);
    }

    return NULL;
}

static inline struct SwiftNetClientConnection* const construct_client_connection(const bool loopback, const uint16_t destination_port, const in_addr_t server_address, pcap_t* const pcap) {
    struct SwiftNetClientConnection* const new_connection = allocator_allocate(&client_connection_memory_allocator);

    struct ether_header eth_header = {
        .ether_dhost = {0xff,0xff,0xff,0xff,0xff,0xff},
        .ether_type = htons(0x0800)
    };

    memcpy(eth_header.ether_shost, mac_address, sizeof(eth_header.ether_shost));

    new_connection->eth_header = eth_header;
    new_connection->pcap = pcap;
    new_connection->port_info = (struct SwiftNetPortInfo){.source_port = rand(), .destination_port = destination_port};
    new_connection->server_addr.s_addr = server_address;
    new_connection->packet_handler = NULL;
    new_connection->loopback = loopback;
    new_connection->addr_type = pcap_datalink(pcap);
    new_connection->prepend_size = PACKET_PREPEND_SIZE(new_connection->addr_type);

    new_connection->pending_messages_memory_allocator = allocator_create(sizeof(struct SwiftNetPendingMessage), 100);
    new_connection->pending_messages = vector_create(100);
    new_connection->packets_sending_memory_allocator = allocator_create(sizeof(struct SwiftNetPacketSending), 100);
    new_connection->packets_sending = vector_create(100);
    new_connection->packets_completed_memory_allocator = allocator_create(sizeof(struct SwiftNetPacketCompleted), 100);
    new_connection->packets_completed = hashmap_create();
    
    new_connection->packet_queue = (struct PacketQueue){
        .first_node = NULL,
        .last_node = NULL
    };

    UNLOCK_ATOMIC_DATA_TYPE(&new_connection->packet_queue.locked);
    UNLOCK_ATOMIC_DATA_TYPE(&new_connection->packet_callback_queue.locked);

    atomic_store_explicit(&new_connection->closing, false, memory_order_release);
    atomic_store_explicit(&new_connection->initialized, false, memory_order_release);
    atomic_store_explicit(&new_connection->packet_handler_user_arg, NULL, memory_order_release);
    
    memset(&new_connection->packet_callback_queue, 0x00, sizeof(struct PacketCallbackQueue));

    return new_connection;
}

static inline void remove_con_from_listener(const struct SwiftNetClientConnection* const con, struct Listener* const listener) {
    LOCK_ATOMIC_DATA_TYPE(&listener->client_connections.locked);

    for (uint16_t i = 0; i < listener->client_connections.size; i++) {
        struct SwiftNetClientConnection* const client_connection = vector_get(&listener->client_connections, i);
        if (client_connection == con) {
            vector_remove(&listener->client_connections, i);
        }
    }

    UNLOCK_ATOMIC_DATA_TYPE(&listener->client_connections.locked);
}

struct SwiftNetClientConnection* swiftnet_create_client(const char* const ip_address, const uint16_t port, const uint32_t timeout_ms) {
    struct in_addr addr;
    inet_aton(ip_address, &addr);
    const uint32_t ip = ntohl(addr.s_addr);
    const bool loopback = (ip >> 24) == 127;

    pcap_t* const pcap = swiftnet_pcap_open(loopback ? LOOPBACK_INTERFACE_NAME : default_network_interface);
    if (unlikely(pcap == NULL)) {
        return NULL;
    }

    struct SwiftNetClientConnection* const new_connection = construct_client_connection(loopback, port, addr.s_addr, pcap);

    // Request the server information, and proccess it
    const struct SwiftNetPacketInfo request_server_information_packet_info = construct_packet_info(
        0x00,
        REQUEST_INFORMATION,
        1,
        0,
        new_connection->port_info
    );

    const struct ip request_server_info_ip_header = construct_ip_header(new_connection->server_addr, PACKET_HEADER_SIZE, rand());
    
    HANDLE_PACKET_CONSTRUCTION(&request_server_info_ip_header, &request_server_information_packet_info, new_connection->addr_type, &new_connection->eth_header, PACKET_HEADER_SIZE + new_connection->prepend_size, request_server_info_buffer)

    HANDLE_CHECKSUM(request_server_info_buffer, sizeof(request_server_info_buffer), new_connection->prepend_size);

    pthread_t send_request_thread;

    const struct RequestServerInformationArgs thread_args = {
        .pcap = pcap,
        .data = request_server_info_buffer,
        .size = sizeof(request_server_info_buffer),
        .server_addr = addr,
        .timeout_ms = timeout_ms,
        .connection = new_connection
    };

    struct Listener* const listener = check_existing_listener(loopback ? LOOPBACK_INTERFACE_NAME : default_network_interface, new_connection, CONNECTION_TYPE_CLIENT, loopback);

    pthread_create(&send_request_thread, NULL, request_server_information, (void*)&thread_args);

    pthread_join(send_request_thread, NULL);

    if (atomic_load_explicit(&new_connection->initialized, memory_order_acquire) == false) {
        atomic_store_explicit(&new_connection->closing, true, memory_order_release);

        pcap_close(new_connection->pcap);

        allocator_free(&client_connection_memory_allocator, new_connection);

        remove_con_from_listener(new_connection, listener);
        
        return NULL;
    }

    pthread_create(&new_connection->process_packets_thread, NULL, swiftnet_client_process_packets, new_connection);
    pthread_create(&new_connection->execute_callback_thread, NULL, execute_packet_callback_client, new_connection);

    pthread_mutex_init(&new_connection->process_packets_mtx, NULL);
    pthread_mutex_init(&new_connection->execute_callback_mtx, NULL);

    pthread_cond_init(&new_connection->process_packets_cond, NULL);
    pthread_cond_init(&new_connection->execute_callback_cond, NULL);

    #ifdef SWIFT_NET_DEBUG
        if (check_debug_flag(INITIALIZATION)) {
            send_debug_message("Successfully initialized client\n");
        }
    #endif

    return new_connection;
}
