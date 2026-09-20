#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdbool.h>
#include "internal/internal.h"
#include "internal/networking.h"
#include "swift_net.h"

static inline struct SwiftNetServer* construct_server(const bool loopback, const uint16_t server_port) {
    struct SwiftNetServer* restrict new_server;
    struct ether_header eth_header;

    new_server = allocator_allocate(&server_memory_allocator);
    eth_header = DEFAULT_MAC_ADDRESS_STRUCT;

    memcpy(eth_header.ether_shost, mac_address, sizeof(eth_header.ether_shost));

    *new_server = (struct SwiftNetServer){
        .eth_header = eth_header,
        .server_port = server_port,
        .loopback = loopback,
        .packet_queue = (struct SwiftNetPacketQueue){
            .first_node = NULL,
            .last_node = NULL
        },
    };

    memset(&new_server->packet_callback_queue, 0x00, sizeof(struct SwiftNetPacketCallbackQueue));

    UNLOCK_ATOMIC_DATA_TYPE(&new_server->packet_queue.locked);
    UNLOCK_ATOMIC_DATA_TYPE(&new_server->packet_callback_queue.locked);

    atomic_store_explicit(&new_server->processing_packets, true, memory_order_release);
    atomic_store_explicit(&new_server->executing_packets, true, memory_order_release);
    atomic_store_explicit(&new_server->packet_handler, NULL, memory_order_release);
    atomic_store_explicit(&new_server->packet_handler_user_arg, NULL, memory_order_release);
    atomic_store_explicit(&new_server->closing, false, memory_order_release);

    new_server->packets_completed = hashmap_create(&packet_completed_key_allocator);
    new_server->packets_sending = hashmap_create(&packet_sending_key_allocator);
    new_server->pending_messages = hashmap_create(&pending_message_key_allocator);

    return new_server;
}

struct SwiftNetServer* swiftnet_create_server(const uint16_t port, const bool loopback) {
    struct SwiftNetServer* new_server;


    new_server = construct_server(loopback, port);
    if(unlikely(new_server == NULL)) {
        PRINT_ERROR("Failed to construct server");
        exit(EXIT_FAILURE);
    }

    // Create a new thread that will handle all packets received
    struct Listener* const new_listener = check_existing_listener(loopback ? SERVER_LOOPBACK_INTERFACE_NAME : default_network_interface, new_server, CONNECTION_TYPE_SERVER, loopback);

    new_server->network_data = new_listener->network_data;

    pthread_create(&new_server->process_packets_thread, NULL, swiftnet_server_process_packets, new_server);
    pthread_create(&new_server->execute_callback_thread, NULL, execute_packet_callback_server, new_server);

    pthread_mutex_init(&new_server->process_packets_mtx, NULL);
    pthread_mutex_init(&new_server->execute_callback_mtx, NULL);

    pthread_cond_init(&new_server->process_packets_cond, NULL);
    pthread_cond_init(&new_server->execute_callback_cond, NULL);

    #ifndef SWIFT_NET_DISABLE_DEBUGGING
        if (check_debug_flag(SWIFTNET_DEBUG_INITIALIZATION)) {
            send_debug_message("Successfully initialized server\n");
        }
    #endif

    return new_server;
}
