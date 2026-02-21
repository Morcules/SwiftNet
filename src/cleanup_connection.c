#include "internal/internal.h"
#include "swift_net.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static inline void cleanup_connection_resources(const enum ConnectionType connection_type, void* const connection) {
    if (connection_type == CONNECTION_TYPE_CLIENT) {
        struct SwiftNetClientConnection* const client = (struct SwiftNetClientConnection*)connection;

        allocator_destroy(&client->packets_sending_memory_allocator);
        allocator_destroy(&client->pending_messages_memory_allocator);
        allocator_destroy(&client->packets_completed_memory_allocator);

        vector_destroy(&client->packets_sending);
        vector_destroy(&client->pending_messages);

        hashmap_destroy(&client->packets_completed);
    } else {
        struct SwiftNetServer* const server = (struct SwiftNetServer*)connection;

        allocator_destroy(&server->packets_sending_memory_allocator);
        allocator_destroy(&server->pending_messages_memory_allocator);
        allocator_destroy(&server->packets_completed_memory_allocator);

        vector_destroy(&server->packets_sending);
        vector_destroy(&server->pending_messages);

        hashmap_destroy(&server->packets_completed);
    }
}

static inline void remove_listener(const enum ConnectionType connection_type, const char* interface_name, void* const connection) {
    vector_lock(&listeners);

    for (uint16_t i = 0; i < listeners.size; i++) {
        struct Listener* const current_listener = vector_get(&listeners, i);
        if (strcmp(interface_name, current_listener->interface_name) == 0) {
            if (connection_type == CONNECTION_TYPE_CLIENT) {
                vector_lock(&current_listener->client_connections);

                for (uint16_t inx = 0; inx < current_listener->client_connections.size; inx++) {
                    struct SwiftNetClientConnection* const current_connection = vector_get(&current_listener->client_connections, i);
                    if (current_connection != connection) {
                        continue;
                    }

                    vector_remove(&current_listener->client_connections, inx);

                    break;
                }

                vector_unlock(&current_listener->client_connections);
            } else {
                vector_lock(&current_listener->servers);

                for (uint16_t inx = 0; inx < current_listener->servers.size; inx++) {
                    struct SwiftNetClientConnection* const current_connection = vector_get(&current_listener->servers, i);
                    if (current_connection != connection) {
                        continue;
                    }

                    vector_remove(&current_listener->servers, inx);

                    break;
                }

                vector_unlock(&current_listener->servers);
            }

            break;
        }
    }

    vector_unlock(&listeners);
}

static inline const char* get_interface_name(const bool loopback) {
    return loopback ? LOOPBACK_INTERFACE_NAME : default_network_interface;
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
    cleanup_connection_resources(CONNECTION_TYPE_CLIENT, client);
    
    const char* interface_name = get_interface_name(client->loopback);

    remove_listener(CONNECTION_TYPE_CLIENT, interface_name, client);

    close_threads(CONNECTION_TYPE_CLIENT, client);

    pcap_close(client->pcap);

    allocator_free(&client_connection_memory_allocator, client);
}

void swiftnet_server_cleanup(struct SwiftNetServer* const server) {
    cleanup_connection_resources(CONNECTION_TYPE_SERVER, server);
    
    const char* interface_name = get_interface_name(server->loopback);

    remove_listener(CONNECTION_TYPE_SERVER, interface_name, server);

    close_threads(CONNECTION_TYPE_SERVER, server);

    pcap_close(server->pcap);

    allocator_free(&server_memory_allocator, server);
}
