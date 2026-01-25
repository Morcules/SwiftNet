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
#include "swift_net.h"

static inline struct SwiftNetServer* const construct_server(const bool loopback, const uint16_t server_port, pcap_t* const pcap) {
    struct SwiftNetServer* const new_server = allocator_allocate(&server_memory_allocator);

    struct ether_header eth_header = {
        .ether_dhost = {0xff,0xff,0xff,0xff,0xff,0xff},
        .ether_type = htons(0x0800)
    };

    memcpy(eth_header.ether_shost, mac_address, sizeof(eth_header.ether_shost));

    new_server->eth_header = eth_header;
    new_server->server_port = server_port;
    new_server->loopback = loopback;
    new_server->pcap = pcap;
    new_server->addr_type = pcap_datalink(pcap);
    new_server->prepend_size = PACKET_PREPEND_SIZE(new_server->addr_type);
    new_server->packet_queue = (struct PacketQueue){
        .first_node = NULL,
        .last_node = NULL
    };

    memset(&new_server->packet_callback_queue, 0x00, sizeof(struct PacketCallbackQueue));

    atomic_store_explicit(&new_server->packet_queue.owner, NONE, memory_order_release);
    atomic_store_explicit(&new_server->packet_callback_queue.owner, NONE, memory_order_release);
    atomic_store_explicit(&new_server->packet_handler, NULL, memory_order_release);
    atomic_store_explicit(&new_server->packet_handler_user_arg, NULL, memory_order_release);
    atomic_store_explicit(&new_server->closing, false, memory_order_release);

    new_server->pending_messages_memory_allocator = allocator_create(sizeof(struct SwiftNetPendingMessage), 100);
    new_server->pending_messages = vector_create(100);
    new_server->packets_sending_memory_allocator = allocator_create(sizeof(struct SwiftNetPacketSending), 100);
    new_server->packets_sending = vector_create(100);
    new_server->packets_completed_memory_allocator = allocator_create(sizeof(struct SwiftNetPacketCompleted), 100);
    new_server->packets_completed = vector_create(100);

    return new_server;
}

struct SwiftNetServer* swiftnet_create_server(const uint16_t port, const bool loopback) {
    // Init pcap device
    pcap_t* const pcap = swiftnet_pcap_open(loopback ? LOOPBACK_INTERFACE_NAME : default_network_interface);
    if (unlikely(pcap == NULL)) {
        PRINT_ERROR("Failed to open bpf");
        return NULL;
    }

    struct SwiftNetServer* const new_server = construct_server(loopback, port, pcap);

    // Create a new thread that will handle all packets received
    check_existing_listener(loopback ? LOOPBACK_INTERFACE_NAME : default_network_interface, new_server, CONNECTION_TYPE_SERVER, loopback);

    pthread_create(&new_server->process_packets_thread, NULL, swiftnet_server_process_packets, new_server);
    pthread_create(&new_server->execute_callback_thread, NULL, execute_packet_callback_server, new_server);

    pthread_mutex_init(&new_server->process_packets_mtx, NULL);
    pthread_mutex_init(&new_server->execute_callback_mtx, NULL);

    pthread_cond_init(&new_server->process_packets_cond, NULL);
    pthread_cond_init(&new_server->execute_callback_cond, NULL);

    #ifdef SWIFT_NET_DEBUG
        if (check_debug_flag(INITIALIZATION)) {
            send_debug_message("Successfully initialized server\n");
        }
    #endif

    return new_server;
}
