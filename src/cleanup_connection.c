#include "swift_net.h"
#include "internal/internal.h"
#include "internal/networking.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline void cleanup_hashmap(struct SwiftNetHashMap* const hashmap, struct SwiftNetMemoryAllocator* const allocator) {
    LOCK_ATOMIC_DATA_TYPE(&hashmap->atomic_lock);

    LOOP_HASHMAP(hashmap, struct SwiftNetPacketCompleted*, 
        hashmap_remove(hashmap_item->key_original_data, hashmap_item->key_original_data_size, hashmap);
        allocator_free(allocator, hashmap_data);
    )


    if (hashmap->size != 0) {
        exit(EXIT_FAILURE);
    }
    UNLOCK_ATOMIC_DATA_TYPE(&hashmap->atomic_lock);

    hashmap_destroy(hashmap);
}

static inline void cleanup_connection_resources(const enum ConnectionType connection_type, void* const connection) {
    if (connection_type == CONNECTION_TYPE_CLIENT) {
        struct SwiftNetClientConnection* const client = connection;

        hashmap_destroy(&client->pending_messages);
        hashmap_destroy(&client->packets_sending);

        cleanup_hashmap(&client->packets_completed, &packet_completed_memory_allocator);
    } else {
        struct SwiftNetServer* const server = connection;

        hashmap_destroy(&server->pending_messages);
        hashmap_destroy(&server->packets_sending);

        cleanup_hashmap(&server->packets_completed, &packet_completed_memory_allocator);
    }
}

static inline void remove_listener(const enum ConnectionType connection_type, char* const restrict interface_name, void* const connection) {
    uint32_t interface_len;
    struct Listener* listener;


    interface_len = (uint32_t)strlen(interface_name);

    LOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);

    listener = hashmap_get(interface_name, interface_len, &listeners);
    if (unlikely(listener == NULL)) {
        UNLOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);

        return;
    }

    if (connection_type == CONNECTION_TYPE_CLIENT) {
        LOCK_ATOMIC_DATA_TYPE(&listener->client_connections.atomic_lock);

        hashmap_remove(&((struct SwiftNetClientConnection*)connection)->port_info.source_port, sizeof(uint16_t), &listener->client_connections);

        UNLOCK_ATOMIC_DATA_TYPE(&listener->client_connections.atomic_lock);
    } else {
        LOCK_ATOMIC_DATA_TYPE(&listener->servers.atomic_lock);

        hashmap_remove(&((struct SwiftNetServer*)connection)->server_port, sizeof(uint16_t), &listener->servers);

        UNLOCK_ATOMIC_DATA_TYPE(&listener->servers.atomic_lock);
    }

    if(listener->servers.size + listener->client_connections.size == 0) {
        hashmap_destroy(&listener->servers);
        hashmap_destroy(&listener->client_connections);

        SWIFTNET_BREAK_RECEIVER_LOOP(&listener->network_data);

        #ifdef SWIFT_NET_BACKEND_PCAP
        pthread_join(listener->listener_thread, NULL);
        #elif defined(SWIFT_NET_BACKEND_DPDK)
        rte_eal_wait_lcore(listener->lcore);

        lcores_used[listener->lcore_internal_index] = listener->lcore;
        #endif

        SWIFTNET_CLOSE_CONNECTION(&listener->network_data);

        allocator_free(&listener_memory_allocator, listener);

        hashmap_remove(interface_name, interface_len, &listeners);
    }

    UNLOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);
}

static inline char* get_interface_name(const bool loopback, const enum ConnectionType con_type) {
    return loopback ? (con_type == CONNECTION_TYPE_CLIENT ? CLIENT_LOOPBACK_INTERFACE_NAME : SERVER_LOOPBACK_INTERFACE_NAME) : default_network_interface;
}

static inline void close_threads(const enum ConnectionType connection_type, void* const connection) {
    if (connection_type == CONNECTION_TYPE_CLIENT) {
        struct SwiftNetClientConnection* const client = connection;

        atomic_store_explicit(&client->closing, true, memory_order_release);

        pthread_mutex_lock(&client->process_packets_mtx);
        pthread_cond_signal(&client->process_packets_cond);
        pthread_mutex_unlock(&client->process_packets_mtx);

        pthread_mutex_lock(&client->execute_callback_mtx);
        pthread_cond_signal(&client->execute_callback_cond);
        pthread_mutex_unlock(&client->execute_callback_mtx);

        pthread_join(client->process_packets_thread, NULL);
        pthread_join(client->execute_callback_thread, NULL);

        pthread_mutex_destroy(&client->process_packets_mtx);
        pthread_mutex_destroy(&client->execute_callback_mtx);

        pthread_cond_destroy(&client->process_packets_cond);
        pthread_cond_destroy(&client->execute_callback_cond);
    } else {
        struct SwiftNetServer* const server = connection;

        atomic_store_explicit(&server->closing, true, memory_order_release);

        pthread_mutex_lock(&server->process_packets_mtx);
        pthread_cond_signal(&server->process_packets_cond);
        pthread_mutex_unlock(&server->process_packets_mtx);

        pthread_mutex_lock(&server->execute_callback_mtx);
        pthread_cond_signal(&server->execute_callback_cond);
        pthread_mutex_unlock(&server->execute_callback_mtx);

        pthread_join(server->process_packets_thread, NULL);
        pthread_join(server->execute_callback_thread, NULL);

        pthread_mutex_destroy(&server->process_packets_mtx);
        pthread_mutex_destroy(&server->execute_callback_mtx);
        
        pthread_cond_destroy(&server->process_packets_cond);
        pthread_cond_destroy(&server->execute_callback_cond);
    }
}

void swiftnet_client_cleanup(struct SwiftNetClientConnection* const client) {
    char* restrict interface_name;

    cleanup_connection_resources(CONNECTION_TYPE_CLIENT, client);
    
    interface_name = get_interface_name(client->loopback, CONNECTION_TYPE_CLIENT);

    remove_listener(CONNECTION_TYPE_CLIENT, interface_name, client);

    close_threads(CONNECTION_TYPE_CLIENT, client);

    allocator_free(&client_connection_memory_allocator, client);
}

void swiftnet_server_cleanup(struct SwiftNetServer* const server) {
    char* restrict interface_name;


    cleanup_connection_resources(CONNECTION_TYPE_SERVER, server);
    
    interface_name = get_interface_name(server->loopback, CONNECTION_TYPE_SERVER);

    remove_listener(CONNECTION_TYPE_SERVER, interface_name, server);

    close_threads(CONNECTION_TYPE_SERVER, server);

    allocator_free(&server_memory_allocator, server);
}
