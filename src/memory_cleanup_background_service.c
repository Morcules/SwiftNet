#include "swift_net.h"
#include "internal/internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static inline void cleanup_packets_completed(struct SwiftNetVector* packets_completed, struct SwiftNetMemoryAllocator* const packets_completed_allocator) {
    vector_lock(packets_completed);

    for (uint32_t i = 0; i < packets_completed->size; i++) {
        struct SwiftNetPacketCompleted* const current_packet_completed = vector_get(packets_completed, i);

        if (current_packet_completed->marked_cleanup == true) {
            vector_remove(packets_completed, i);

            allocator_free(packets_completed_allocator, current_packet_completed);
        } else {
            current_packet_completed->marked_cleanup = true;
        }
    }

    vector_unlock(packets_completed);
}

void* memory_cleanup_background_service() {
    while(atomic_load_explicit(&swiftnet_closing, memory_order_acquire) == false) {
        struct timeval start, end;
        gettimeofday(&start, NULL);

        vector_lock(&listeners);

        for (uint32_t i = 0; i < listeners.size; i++) {
            struct Listener* const current_listener = vector_get(&listeners, i);

            struct SwiftNetVector* const client_connections = &current_listener->client_connections;
            struct SwiftNetVector* const servers = &current_listener->servers;

            vector_lock(servers);
            vector_lock(client_connections);

            for (uint32_t client_connection_index = 0; client_connection_index < client_connections->size; client_connection_index++) {
                struct SwiftNetClientConnection* const current_con = vector_get(client_connections, client_connection_index);

                //cleanup_packets_completed(&current_con->packets_completed, &current_con->packets_completed_memory_allocator);
            }

            for (uint32_t server_index = 0; server_index < servers->size; server_index++) {
                struct SwiftNetServer* const current_server = vector_get(servers, server_index);

                //cleanup_packets_completed(&current_server->packets_completed, &current_server->packets_completed_memory_allocator);
            }

            vector_unlock(client_connections);
            vector_unlock(servers);
        }

        vector_unlock(&listeners);

        gettimeofday(&end, NULL);

        uint32_t diff_us = (uint32_t)((end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));

        if (diff_us > PACKET_HISTORY_STORE_TIME * 1000000) {
            continue;
        }

        usleep((PACKET_HISTORY_STORE_TIME * 1000000) - diff_us);
    }

    return NULL;
}
