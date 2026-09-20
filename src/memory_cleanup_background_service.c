#include "swift_net.h"
#include "internal/internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

static inline void cleanup_packets_completed(struct SwiftNetHashMap* const packets_completed, const bool closing) {
    LOCK_ATOMIC_DATA_TYPE(&packets_completed->atomic_lock);

    LOOP_HASHMAP(packets_completed, struct SwiftNetPacketCompleted*, 
        if (closing) {
            hashmap_remove(hashmap_item->key_original_data, hashmap_item->key_original_data_size, packets_completed);
            allocator_free(&packet_completed_memory_allocator, hashmap_data);
        }

        if (hashmap_data->marked_cleanup == true) {
            hashmap_remove(hashmap_item->key_original_data, hashmap_item->key_original_data_size, packets_completed);

            allocator_free(&packet_completed_memory_allocator, hashmap_data);
        } else {
            ((struct SwiftNetPacketCompleted*)hashmap_data)->marked_cleanup = true;
        }
    )

    UNLOCK_ATOMIC_DATA_TYPE(&packets_completed->atomic_lock);
}

static inline void cleanup_pending_messages(struct SwiftNetHashMap* const pending_messages, const bool closing) {
    LOCK_ATOMIC_DATA_TYPE(&pending_messages->atomic_lock);

    LOOP_HASHMAP(pending_messages, struct SwiftNetPendingMessage*, 
        if (closing) {
            hashmap_remove(hashmap_item->key_original_data, hashmap_item->key_original_data_size, pending_messages);
            allocator_free(&pending_message_memory_allocator, hashmap_data);
        }

        if (hashmap_data->bg_last_chunks_received != hashmap_data->chunks_received_number) {
            hashmap_data->marked_cleanup = false;
            hashmap_data->bg_last_chunks_received = hashmap_data->chunks_received_number;

            continue;
        }

        if (((struct SwiftNetPendingMessage*)hashmap_data)->marked_cleanup == true) {
            hashmap_remove(hashmap_item->key_original_data, hashmap_item->key_original_data_size, pending_messages);

            allocator_free(&pending_message_memory_allocator, hashmap_data);
        } else {
            ((struct SwiftNetPendingMessage*)hashmap_data)->marked_cleanup = true;
        }
    )

    UNLOCK_ATOMIC_DATA_TYPE(&pending_messages->atomic_lock);
}

static inline void handle_listener(struct Listener* const current_listener, const bool closing) {
    struct SwiftNetHashMap* const client_connections = &current_listener->client_connections;
    struct SwiftNetHashMap* const servers = &current_listener->servers;

    LOCK_ATOMIC_DATA_TYPE(&servers->atomic_lock);
    LOCK_ATOMIC_DATA_TYPE(&client_connections->atomic_lock);

    LOOP_HASHMAP(client_connections, struct SwiftNetClientConnection*,
        cleanup_packets_completed(&hashmap_data->packets_completed, closing);
        cleanup_pending_messages(&hashmap_data->pending_messages, closing);
    )

    LOOP_HASHMAP(servers, struct SwiftNetClientConnection*,
        cleanup_packets_completed(&hashmap_data->packets_completed, closing);
        cleanup_pending_messages(&hashmap_data->pending_messages,  closing);
    )

    UNLOCK_ATOMIC_DATA_TYPE(&servers->atomic_lock);
    UNLOCK_ATOMIC_DATA_TYPE(&client_connections->atomic_lock);
}

void* memory_cleanup_background_service(MAYBE_UNUSED void* user) {
    struct timeval start, end;
    suseconds_t elapsed_us;
    suseconds_t target_us = (suseconds_t)(PACKET_HISTORY_STORE_TIME * 1000000ULL);
    bool closing;

    goto start_loop;


start_loop:
    gettimeofday(&start, NULL);

    closing = atomic_load_explicit(&swiftnet_closing, memory_order_acquire);

    if(closing) return NULL;

    LOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);

    LOOP_HASHMAP(&listeners, struct Listener*,
        handle_listener(hashmap_data, closing);
    )

    UNLOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);

    gettimeofday(&end, NULL);

    elapsed_us = (suseconds_t)((end.tv_sec - start.tv_sec) * 1000000LL) + (end.tv_usec - start.tv_usec);

    if (elapsed_us < target_us) {
        usleep((useconds_t)(target_us - elapsed_us));
    }

    goto start_loop;
}
