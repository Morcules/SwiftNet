#include "internal/internal.h"
#include "internal/networking.h"
#include "swift_net.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

static inline void close_listeners() {
    LOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);

    struct SwiftNetHashMap* const listeners_map = &listeners;

    LOOP_HASHMAP(listeners_map,
        struct Listener* const current_listener = hashmap_data;

        SWIFTNET_BREAK_RECEIVER_LOOP(&current_listener->network_data);

        pthread_join(current_listener->listener_thread, NULL);

        SWIFTNET_CLOSE_CONNECTION(&current_listener->network_data);

        hashmap_destroy(&current_listener->client_connections);
        hashmap_destroy(&current_listener->servers);
    )

    hashmap_destroy(&listeners);
}

static inline void close_background_service() {
    atomic_store_explicit(&swiftnet_closing, true, memory_order_release);

    pthread_join(memory_cleanup_thread, NULL);
}

void swiftnet_cleanup() {
    allocator_destroy(&packet_queue_node_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&packet_callback_queue_node_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&server_packet_data_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&client_packet_data_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&packet_buffer_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&hashmap_item_memory_allocator ENABLE_INTERNAL_CHECK);
    
    #ifdef SWIFT_NET_REQUESTS
        allocator_destroy(&requests_sent_memory_allocator ENABLE_INTERNAL_CHECK);

        hashmap_destroy(&requests_sent);
    #endif

    close_listeners();
    
    allocator_destroy(&server_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&client_connection_memory_allocator ENABLE_INTERNAL_CHECK);

    allocator_destroy(&listener_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&uint16_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&packet_completed_key_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&pending_message_key_allocator ENABLE_INTERNAL_CHECK);

    #ifdef SWIFT_NET_INTERNAL_TESTING
    printf("Bytes leaked: %d\nItems leaked: %d\n", bytes_leaked, items_leaked);
    #endif

    close_background_service();
}
