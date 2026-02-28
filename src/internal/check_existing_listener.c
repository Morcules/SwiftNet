#include "internal.h"
           
void* check_existing_listener(const char* interface_name, void* const connection, const enum ConnectionType connection_type, const bool loopback) {
    LOCK_ATOMIC_DATA_TYPE(&listeners.locked);

    for (uint16_t i = 0; i < listeners.size; i++) {
        struct Listener* const current_listener = vector_get(&listeners, i);
        if (strcmp(interface_name, current_listener->interface_name) == 0) {
            if (connection_type == CONNECTION_TYPE_CLIENT) {
                LOCK_ATOMIC_DATA_TYPE(&current_listener->client_connections.locked);

                vector_push(&current_listener->client_connections, connection);

                UNLOCK_ATOMIC_DATA_TYPE(&current_listener->client_connections.locked);
            } else {
                LOCK_ATOMIC_DATA_TYPE(&current_listener->servers.locked);

                vector_push(&current_listener->servers, connection);

                UNLOCK_ATOMIC_DATA_TYPE(&current_listener->servers.locked);
            }

            UNLOCK_ATOMIC_DATA_TYPE(&listeners.locked);

            return current_listener;
        }
    }

    struct Listener* const new_listener = allocator_allocate(&listener_memory_allocator);
    new_listener->servers = vector_create(10);
    new_listener->client_connections = vector_create(10);
    new_listener->pcap = swiftnet_pcap_open(interface_name);
    new_listener->addr_type = pcap_datalink(new_listener->pcap);
    memcpy(new_listener->interface_name, interface_name, strlen(interface_name) + 1);
    new_listener->loopback = loopback;

    if (connection_type == CONNECTION_TYPE_CLIENT) {
        vector_push(&new_listener->client_connections, connection);
    } else {
        vector_push(&new_listener->servers, connection);
    }

    vector_push(&listeners, new_listener);

    UNLOCK_ATOMIC_DATA_TYPE(&listeners.locked);

    pthread_create(&new_listener->listener_thread, NULL, interface_start_listening, new_listener);

    return new_listener;
}
