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
#include "internal/networking.h"

struct RequestServerInformationArgs {
    uint32_t size;
    struct in_addr server_addr;
    struct SwiftNetNetworkData* restrict network_data;
    uint32_t timeout_ms;
    void* restrict data;
    struct SwiftNetClientConnection* connection;
};

void* request_server_information(void* restrict const request_server_information_args_void) {
    const struct RequestServerInformationArgs* restrict const request_server_information_args = request_server_information_args_void;

    struct timeval tv;
    uint32_t start;
    uint32_t end;

    gettimeofday(&tv, NULL);

    start = (uint32_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

    goto init_connection_request;


init_connection_request:
    gettimeofday(&tv, NULL);

    end = (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);

    if (end > start + request_server_information_args->timeout_ms) goto exit;

    if(atomic_load_explicit(&request_server_information_args->connection->initialized, memory_order_acquire) == true) {
        goto exit;
    }

    #ifdef SWIFT_NET_DEBUG
        if (check_debug_flag(SWIFTNET_DEBUG_INITIALIZATION)) {
            send_debug_message("Requested server information: {\"server_ip_address\": \"%s\"}\n", inet_ntoa(request_server_information_args->server_addr));
        }
    #endif

    SWIFTNET_SEND_PACKET(request_server_information_args->network_data, request_server_information_args->data, request_server_information_args->size);

    usleep(250000);

    goto init_connection_request;


exit:
    return NULL;
}

static inline struct SwiftNetClientConnection* const construct_client_connection(const bool loopback, const uint16_t destination_port, const in_addr_t server_address, struct SwiftNetNetworkData* const network_data) {
    struct SwiftNetClientConnection* const new_connection = allocator_allocate(&client_connection_memory_allocator);

    struct ether_header eth_header = {
        .ether_dhost = {0xff,0xff,0xff,0xff,0xff,0xff},
        .ether_type = htons(0x0800)
    };


    memcpy(eth_header.ether_shost, mac_address, sizeof(eth_header.ether_shost));

    *new_connection = (struct SwiftNetClientConnection){
        .eth_header = eth_header,
        .port_info = (struct SwiftNetPortInfo){.source_port = rand(), .destination_port = destination_port},
        .server_addr.s_addr = server_address,
        .packet_handler = NULL,
        .loopback = loopback,
        .network_data = *network_data,
        .pending_messages_memory_allocator = allocator_create(sizeof(struct SwiftNetPendingMessage), 40 * SWIFT_NET_MEMORY_USAGE),
        .packets_sending_memory_allocator = allocator_create(sizeof(struct SwiftNetPacketSending), 40 * SWIFT_NET_MEMORY_USAGE),
        .packets_completed_memory_allocator = allocator_create(sizeof(struct SwiftNetPacketCompleted), 40 * SWIFT_NET_MEMORY_USAGE),
        .packets_completed = hashmap_create(&packet_completed_key_allocator),
        .packets_sending = hashmap_create(&uint16_memory_allocator),
        .pending_messages = hashmap_create(&pending_message_key_allocator),
        .packet_queue = (struct PacketQueue){
            .first_node = NULL,
            .last_node = NULL
        },
    };

    UNLOCK_ATOMIC_DATA_TYPE(&new_connection->packet_queue.locked);
    UNLOCK_ATOMIC_DATA_TYPE(&new_connection->packet_callback_queue.locked);

    atomic_store_explicit(&new_connection->processing_packets, true, memory_order_release);
    atomic_store_explicit(&new_connection->closing, false, memory_order_release);
    atomic_store_explicit(&new_connection->initialized, false, memory_order_release);
    atomic_store_explicit(&new_connection->packet_handler_user_arg, NULL, memory_order_release);
    
    memset(&new_connection->packet_callback_queue, 0x00, sizeof(struct PacketCallbackQueue));

    return new_connection;
}

static inline void remove_con_from_listener(struct SwiftNetClientConnection* const con, struct Listener* const listener) {
    LOCK_ATOMIC_DATA_TYPE(&listener->client_connections.atomic_lock);

    hashmap_remove(&con->port_info.source_port, sizeof(uint16_t), &listener->client_connections);

    UNLOCK_ATOMIC_DATA_TYPE(&listener->client_connections.atomic_lock);
}

struct SwiftNetClientConnection* swiftnet_create_client(const char* const ip_address, const uint16_t port, const uint32_t timeout_ms) {
    struct in_addr addr;
    uint32_t ip;
    bool loopback;
    struct SwiftNetClientConnection* new_connection;
    struct SwiftNetPacketInfo request_server_information_packet_info;
    struct ip request_server_info_ip_header;
    pthread_t send_request_thread;
    struct RequestServerInformationArgs thread_args;
    struct Listener* listener;
    struct SwiftNetNetworkData net_data;
    struct SwiftNetNetworkData null_net_data;


    goto init_connection;


init_connection:
    inet_aton(ip_address, &addr);

    ip = ntohl(addr.s_addr);

    loopback = (ip >> 24) == 127;

    net_data = swiftnet_initialize_networking(loopback ? LOOPBACK_INTERFACE_NAME : default_network_interface);

    memset(&null_net_data, 0, sizeof(null_net_data));
    if (unlikely(memcmp(&null_net_data, &net_data, sizeof(net_data))) == 0) {
        return NULL;
    }

    new_connection = construct_client_connection(loopback, port, addr.s_addr, &net_data);

    goto request_initialization;


request_initialization:
    // Request the server information, and proccess it
    request_server_information_packet_info = construct_packet_info(
        0x00,
        REQUEST_INFORMATION,
        1,
        0,
        new_connection->port_info
    );

    request_server_info_ip_header = construct_ip_header(new_connection->server_addr, PACKET_HEADER_SIZE, rand());
    
    HANDLE_PACKET_CONSTRUCTION(&request_server_info_ip_header, &request_server_information_packet_info, &net_data, &new_connection->eth_header, PACKET_HEADER_SIZE + GET_PREPEND_SIZE(&new_connection->network_data), request_server_info_buffer);

    HANDLE_CHECKSUM(request_server_info_buffer, sizeof(request_server_info_buffer), &net_data);

    thread_args = (struct RequestServerInformationArgs){
        .network_data = &net_data,
        .data = request_server_info_buffer,
        .size = sizeof(request_server_info_buffer),
        .server_addr = addr,
        .timeout_ms = timeout_ms,
        .connection = new_connection
    };

    listener = check_existing_listener(loopback ? LOOPBACK_INTERFACE_NAME : default_network_interface, new_connection, CONNECTION_TYPE_CLIENT, loopback);

    pthread_create(&send_request_thread, NULL, request_server_information, (void*)&thread_args);

    pthread_join(send_request_thread, NULL);

    if (atomic_load_explicit(&new_connection->initialized, memory_order_acquire) == false) {
        atomic_store_explicit(&new_connection->closing, true, memory_order_release);

        swiftnet_close_connection(&new_connection->network_data);

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
        if (check_debug_flag(SWIFTNET_DEBUG_INITIALIZATION)) {
            send_debug_message("Successfully initialized client\n");
        }
    #endif

    return new_connection;
}
