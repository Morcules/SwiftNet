#include "internal/internal.h"
#include "swift_net.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static struct PacketCallbackQueueNode *const wait_for_next_packet_callback(struct PacketCallbackQueue* const packet_queue) {
    struct PacketCallbackQueueNode* restrict node_to_process;


    LOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

    if (packet_queue->first_node == NULL) {
        UNLOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);
        return NULL;
    }

    node_to_process = packet_queue->first_node;

    if (node_to_process->next == NULL) {
        packet_queue->first_node = NULL;
        packet_queue->last_node = NULL;

        UNLOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

        return node_to_process;
    }

    packet_queue->first_node = node_to_process->next;

    UNLOCK_ATOMIC_DATA_TYPE(&packet_queue->locked);

    return node_to_process;
}

static inline void remove_pending_message_from_hashmap(struct SwiftNetHashMap* const pending_messages, struct SwiftNetPendingMessage* restrict const pending_message) {
    struct PendingMessagesKey key = {.source_port = pending_message->source_port, .packet_id = pending_message->packet_id};


    LOCK_ATOMIC_DATA_TYPE(&pending_messages->atomic_lock);

    hashmap_remove(&key, sizeof(key), pending_messages);

    UNLOCK_ATOMIC_DATA_TYPE(&pending_messages->atomic_lock);
}

void execute_packet_callback(
    struct PacketCallbackQueue* const queue,
    void (*const _Atomic * const packet_handler)(void *const, void *const),
    const enum ConnectionType connection_type,
    struct SwiftNetMemoryAllocator* const pending_message_memory_allocator,
    const _Atomic bool * const closing,
    void * const connection,
    struct SwiftNetHashMap* const pending_messages,
    _Atomic(void *) * const user_data,
    pthread_mutex_t* const execute_callback_mtx,
    pthread_cond_t* const execute_callback_cond
) {
    void (*packet_handler_loaded)(void *const, void *const);

    struct PacketCallbackQueueNode* restrict current_node;


    goto check_packet;


check_packet:
    if (unlikely(atomic_load_explicit(closing, memory_order_acquire) == true)) {
        return;
    }

    pthread_mutex_lock(execute_callback_mtx);

    current_node = wait_for_next_packet_callback(queue);
    if (current_node == NULL) {
        pthread_cond_wait(execute_callback_cond, execute_callback_mtx);

        pthread_mutex_unlock(execute_callback_mtx);

        goto check_packet;
    }

    pthread_mutex_unlock(execute_callback_mtx);

    packet_handler_loaded = atomic_load_explicit(packet_handler, memory_order_acquire);

    if (current_node->packet_data == NULL) {
        goto next;
    }

    if (current_node->pending_message != NULL) {
        remove_pending_message_from_hashmap(pending_messages, current_node->pending_message);
    }

    goto execute_callback;


execute_callback:
    if (unlikely(packet_handler_loaded == NULL)) {
        if (connection_type == CONNECTION_TYPE_CLIENT) {
            swiftnet_client_destroy_packet_data(current_node->packet_data, connection);
        } else {
            swiftnet_server_destroy_packet_data(current_node->packet_data, connection);
        }

        goto next;
    }

    (*packet_handler_loaded)(current_node->packet_data, atomic_load_explicit(user_data, memory_order_acquire));

    goto next;


next:
    allocator_free(&packet_callback_queue_node_memory_allocator, current_node);

    goto check_packet;
}

void* execute_packet_callback_client(void* const void_client) {
    struct SwiftNetClientConnection* const client = void_client;

    execute_packet_callback(
        &client->packet_callback_queue, 
        (void *)&client->packet_handler,
        CONNECTION_TYPE_CLIENT, 
        &client->pending_messages_memory_allocator,
        &client->closing, void_client,
        &client->pending_messages,
        &client->packet_handler_user_arg,
        &client->execute_callback_mtx,
        &client->execute_callback_cond
    );

    return NULL;
}

void* execute_packet_callback_server(void* const void_server) {
    struct SwiftNetServer* const server = void_server;

    execute_packet_callback(
        &server->packet_callback_queue,
        (void *)&server->packet_handler,
        CONNECTION_TYPE_SERVER,
        &server->pending_messages_memory_allocator,
        &server->closing,
        void_server, &server->pending_messages,
        &server->packet_handler_user_arg,
        &server->execute_callback_mtx,
        &server->execute_callback_cond
    );

    return NULL;
}
