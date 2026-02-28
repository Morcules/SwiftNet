#include "internal/internal.h"
#include "swift_net.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

static struct PacketCallbackQueueNode* const wait_for_next_packet_callback(struct PacketCallbackQueue* const packet_queue) {
    LOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

    if(packet_queue->first_node == NULL) {
        UNLOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);
        return NULL;
    }

    struct PacketCallbackQueueNode* const node_to_process = packet_queue->first_node;

    if(node_to_process->next == NULL) {
        packet_queue->first_node = NULL;
        packet_queue->last_node = NULL;

        UNLOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

        return node_to_process;
    }

    packet_queue->first_node = node_to_process->next;

    UNLOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

    return node_to_process;
}

static inline void remove_pending_message_from_vector(struct SwiftNetVector* const pending_messages, struct SwiftNetPendingMessage* const pending_message) {
    LOCK_ATOMIC_DATA_TYPE(&pending_messages->locked);

    for (uint32_t i = 0; i < pending_messages->size; i++) {
        const struct SwiftNetPendingMessage* const current_pending_message = vector_get(pending_messages, i);
        if (current_pending_message == pending_message) {
            vector_remove(pending_messages, i);
        }
    }

    UNLOCK_ATOMIC_DATA_TYPE(&pending_messages->locked);
}

void execute_packet_callback(
    struct PacketCallbackQueue* const queue,
	void (* const _Atomic * const packet_handler) (void* const,
	void* const),
	const enum ConnectionType connection_type,
	struct SwiftNetMemoryAllocator* const pending_message_memory_allocator,
	_Atomic bool* closing,
	void* const connection,
	struct SwiftNetVector* const pending_messages,
	_Atomic(void*)* user_data,
    pthread_mutex_t* const execute_callback_mtx,
    pthread_cond_t* const execute_callback_cond
) {
    while (1) {
        if (atomic_load_explicit(closing, memory_order_acquire) == true) {
            break;
        }

        pthread_mutex_lock(execute_callback_mtx);

        const struct PacketCallbackQueueNode* const node = wait_for_next_packet_callback(queue);
        if(node == NULL) {
            pthread_cond_wait(execute_callback_cond, execute_callback_mtx);

            pthread_mutex_unlock(execute_callback_mtx);

            continue;
        }

        pthread_mutex_unlock(execute_callback_mtx);

        atomic_thread_fence(memory_order_acquire);

        if(node->packet_data == NULL) {
            allocator_free(&packet_callback_queue_node_memory_allocator, (void*)node);
            continue;
        }

        if(node->pending_message != NULL) {
            remove_pending_message_from_vector(pending_messages, node->pending_message);
        }

        void (*const packet_handler_loaded)(void* const, void* const) = atomic_load(packet_handler);
        if (unlikely(packet_handler_loaded == NULL)) {
            if (connection_type == CONNECTION_TYPE_CLIENT) {
                swiftnet_client_destroy_packet_data(node->packet_data, connection);
            } else {
                swiftnet_client_destroy_packet_data(node->packet_data, connection);
            }

            allocator_free(&packet_callback_queue_node_memory_allocator, (void*)node);

            continue;
        }

        (*packet_handler_loaded)(node->packet_data, atomic_load_explicit(user_data, memory_order_acquire));

        allocator_free(&packet_callback_queue_node_memory_allocator, (void*)node);
    }
}

void* execute_packet_callback_client(void* const void_client) {
    struct SwiftNetClientConnection* const client = void_client;

    execute_packet_callback(&client->packet_callback_queue, (void*)&client->packet_handler, CONNECTION_TYPE_CLIENT, &client->pending_messages_memory_allocator, &client->closing, void_client, &client->pending_messages, &client->packet_handler_user_arg, &client->execute_callback_mtx, &client->execute_callback_cond);

    return NULL;
}

void* execute_packet_callback_server(void* const void_server) {
    struct SwiftNetServer* const server = void_server;

    execute_packet_callback(&server->packet_callback_queue, (void*)&server->packet_handler, CONNECTION_TYPE_SERVER, &server->pending_messages_memory_allocator, &server->closing, void_server, &server->pending_messages, &server->packet_handler_user_arg, &server->execute_callback_mtx, &server->execute_callback_cond);

    return NULL;
}
