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

void* memory_cleanup_background_service() {
    while(atomic_load_explicit(&swiftnet_closing, memory_order_acquire) == false) {
        struct timeval start, end;
        gettimeofday(&start, NULL);

        LOCK_ATOMIC_DATA_TYPE(&listeners.locked);

        for (uint32_t i = 0; i < listeners.size; i++) {
            struct Listener* const current_listener = vector_get(&listeners, i);

            struct SwiftNetVector* const client_connections = &current_listener->client_connections;
            struct SwiftNetVector* const servers = &current_listener->servers;

            LOCK_ATOMIC_DATA_TYPE(&servers->locked);
            LOCK_ATOMIC_DATA_TYPE(&client_connections->locked);

            for (uint32_t client_connection_index = 0; client_connection_index < client_connections->size; client_connection_index++) {
                struct SwiftNetClientConnection* const current_con = vector_get(client_connections, client_connection_index);

                cleanup_packets_completed(&current_con->packets_completed, &current_con->packets_completed_memory_allocator);
            }

            for (uint32_t server_index = 0; server_index < servers->size; server_index++) {
                struct SwiftNetServer* const current_server = vector_get(servers, server_index);

                cleanup_packets_completed(&current_server->packets_completed, &current_server->packets_completed_memory_allocator);
            }

            UNLOCK_ATOMIC_DATA_TYPE(&servers->locked);
            UNLOCK_ATOMIC_DATA_TYPE(&client_connections->locked);
        }

        UNLOCK_ATOMIC_DATA_TYPE(&listeners.locked);

        gettimeofday(&end, NULL);

        uint32_t diff_us = (uint32_t)((end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));

        if (diff_us > PACKET_HISTORY_STORE_TIME * 1000000) {
            continue;
        }

        usleep((PACKET_HISTORY_STORE_TIME * 1000000) - diff_us);
    }

    return NULL;
}
