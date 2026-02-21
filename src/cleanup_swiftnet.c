#include "internal/internal.h"
#include "swift_net.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

static inline void close_listeners() {
    vector_lock(&listeners);

    for (uint16_t i = 0; i < listeners.size; i++) {
        struct Listener* const current_listener = vector_get(&listeners, i);

        pcap_breakloop(current_listener->pcap);

        pthread_join(current_listener->listener_thread, NULL);

        pcap_close(current_listener->pcap);

        vector_destroy(&current_listener->client_connections);
        vector_destroy(&current_listener->servers);
    }

    vector_destroy(&listeners);
}

static inline void close_background_service() {
    atomic_store_explicit(&swiftnet_closing, true, memory_order_release);

    pthread_join(memory_cleanup_thread, NULL);
}

void swiftnet_cleanup() {
    allocator_destroy(&packet_queue_node_memory_allocator);
    allocator_destroy(&packet_callback_queue_node_memory_allocator);
    allocator_destroy(&server_packet_data_memory_allocator);
    allocator_destroy(&client_packet_data_memory_allocator);
    allocator_destroy(&packet_buffer_memory_allocator);
    allocator_destroy(&hashmap_item_memory_allocator);
    
    #ifdef SWIFT_NET_REQUESTS
        allocator_destroy(&requests_sent_memory_allocator);

        vector_destroy(&requests_sent);
    #endif

    close_listeners();
    
    allocator_destroy(&server_memory_allocator);
    allocator_destroy(&client_connection_memory_allocator);

    allocator_destroy(&listener_memory_allocator);
    allocator_destroy(&uint16_memory_allocator);

    #ifdef SWIFT_NET_INTERNAL_TESTING
    printf("Bytes leaked: %d\nItems leaked: %d\n", bytes_leaked, items_leaked);
    #endif

    close_background_service();
}
