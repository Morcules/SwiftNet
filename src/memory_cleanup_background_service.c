#include "swift_net.h"
#include "internal/internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static inline void cleanup_packets_completed(struct SwiftNetHashMap* packets_completed, struct SwiftNetMemoryAllocator* const packets_completed_allocator) {
    LOCK_ATOMIC_DATA_TYPE(&packets_completed->atomic_lock);

    LOOP_HASHMAP(packets_completed, 
        if (((struct SwiftNetPacketCompleted*)hashmap_data)->marked_cleanup == true) {
            hashmap_remove(hashmap_item->key_original_data, hashmap_item->key_original_data_size, packets_completed);

            allocator_free(packets_completed_allocator, hashmap_data);
        } else {
            ((struct SwiftNetPacketCompleted*)hashmap_data)->marked_cleanup = true;
        }
    )

    UNLOCK_ATOMIC_DATA_TYPE(&packets_completed->atomic_lock);
}

static inline void handle_listener(struct Listener* const current_listener) {
    struct SwiftNetHashMap* const client_connections = &current_listener->client_connections;
    struct SwiftNetHashMap* const servers = &current_listener->servers;

    LOCK_ATOMIC_DATA_TYPE(&servers->atomic_lock);
    LOCK_ATOMIC_DATA_TYPE(&client_connections->atomic_lock);

    LOOP_HASHMAP(client_connections,
        struct SwiftNetClientConnection* const client_connection = hashmap_data;
        cleanup_packets_completed(&client_connection->packets_completed, &client_connection->packets_completed_memory_allocator);
    )

    LOOP_HASHMAP(servers,
        struct SwiftNetServer* const server = hashmap_data;
        cleanup_packets_completed(&server->packets_completed, &server->packets_completed_memory_allocator);
    )

    UNLOCK_ATOMIC_DATA_TYPE(&servers->atomic_lock);
    UNLOCK_ATOMIC_DATA_TYPE(&client_connections->atomic_lock);
}

void* memory_cleanup_background_service() {
    while(atomic_load_explicit(&swiftnet_closing, memory_order_acquire) == false) {
        struct timeval start, end;
        gettimeofday(&start, NULL);

        LOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);

        struct SwiftNetHashMap* const listeners_map = &listeners;

        LOOP_HASHMAP(listeners_map,
            handle_listener(hashmap_data);
        )

        UNLOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);

        gettimeofday(&end, NULL);

        uint32_t diff_us = (uint32_t)((end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));

        if (diff_us > PACKET_HISTORY_STORE_TIME * 1000000) {
            continue;
        }

        usleep((PACKET_HISTORY_STORE_TIME * 1000000) - diff_us);
    }

    return NULL;
}
