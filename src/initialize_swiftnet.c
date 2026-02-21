#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include "swift_net.h"
#include "internal/internal.h"
#include <unistd.h>

#ifdef SWIFT_NET_DEBUG
    struct SwiftNetDebugger debugger = {.flags = 0};
#endif

#ifdef SWIFT_NET_INTERNAL_TESTING
    uint32_t bytes_leaked = 0;
    uint32_t items_leaked = 0;
#endif

uint32_t semaphore_counter = 0x00;

uint32_t maximum_transmission_unit = 0x00;
struct in_addr private_ip_address;
uint8_t mac_address[6];
char default_network_interface[SIZEOF_FIELD(struct ifreq, ifr_name)];

struct SwiftNetMemoryAllocator packet_queue_node_memory_allocator;
struct SwiftNetMemoryAllocator packet_callback_queue_node_memory_allocator;
struct SwiftNetMemoryAllocator server_packet_data_memory_allocator;
struct SwiftNetMemoryAllocator client_packet_data_memory_allocator;
struct SwiftNetMemoryAllocator packet_buffer_memory_allocator;
struct SwiftNetMemoryAllocator server_memory_allocator;
struct SwiftNetMemoryAllocator client_connection_memory_allocator;
struct SwiftNetMemoryAllocator listener_memory_allocator;
struct SwiftNetMemoryAllocator hashmap_item_memory_allocator;

#ifdef SWIFT_NET_REQUESTS
    struct SwiftNetMemoryAllocator requests_sent_memory_allocator;
    struct SwiftNetVector requests_sent;
#endif

struct SwiftNetVector listeners;

pthread_t memory_cleanup_thread;

_Atomic bool swiftnet_closing;

static inline void initialize_allocators() {
    packet_queue_node_memory_allocator = allocator_create(sizeof(struct PacketQueueNode), 100);
    packet_callback_queue_node_memory_allocator = allocator_create(sizeof(struct PacketCallbackQueueNode), 100);
    server_packet_data_memory_allocator = allocator_create(sizeof(struct SwiftNetServerPacketData), 100);
    client_packet_data_memory_allocator = allocator_create(sizeof(struct SwiftNetClientPacketData), 100);
    packet_buffer_memory_allocator = allocator_create(maximum_transmission_unit + sizeof(struct ether_header), 100);
    server_memory_allocator = allocator_create(sizeof(struct SwiftNetServer), 10);
    client_connection_memory_allocator = allocator_create(sizeof(struct SwiftNetClientConnection), 10);
    listener_memory_allocator = allocator_create(sizeof(struct Listener), 100);
    hashmap_item_memory_allocator = allocator_create(sizeof(struct SwiftNetHashMapItem), 0xFF);
    
    #ifdef SWIFT_NET_REQUESTS
    requests_sent_memory_allocator = allocator_create(sizeof(struct RequestSent), 100);
    #endif

}

static inline void initialize_vectors() {
    #ifdef SWIFT_NET_REQUESTS
    requests_sent = vector_create(100);
    #endif

    listeners = vector_create(10);
}

static inline void initialize_memory_cleanup_thread() {
    pthread_create(&memory_cleanup_thread, NULL, memory_cleanup_background_service, NULL);
}

void swiftnet_initialize() {
    seed = rand();

    atomic_store_explicit(&swiftnet_closing, false, memory_order_release);

    const int temp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_socket < 0) {
        PRINT_ERROR("Failed to create temp socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in remote = {0};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr);

    if (connect(temp_socket, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        PRINT_ERROR("Failed to connect temp socket");
        close(temp_socket);
        exit(EXIT_FAILURE);
    }

    struct sockaddr private_sockaddr;
    socklen_t private_sockaddr_len = sizeof(private_sockaddr);

    if(getsockname(temp_socket, &private_sockaddr, &private_sockaddr_len) == -1) {
        PRINT_ERROR("Failed to get private ip address");
        close(temp_socket);
        exit(EXIT_FAILURE);
    }

    private_ip_address = ((struct sockaddr_in *)&private_sockaddr)->sin_addr;

    const int got_default_interface = get_default_interface_and_mac(default_network_interface, sizeof(default_network_interface), mac_address, temp_socket);
    if(unlikely(got_default_interface != 0)) {
        PRINT_ERROR("Failed to get the default interface");
        close(temp_socket);
        exit(EXIT_FAILURE);
    }

    maximum_transmission_unit = get_mtu(default_network_interface, temp_socket);
    if(unlikely(maximum_transmission_unit == 0)) {
        PRINT_ERROR("Failed to get the maximum transmission unit");
        close(temp_socket);
        exit(EXIT_FAILURE);
    }

    close(temp_socket);

    initialize_allocators();
    initialize_vectors();

    initialize_memory_cleanup_thread();

    return;
}
