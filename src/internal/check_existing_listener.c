#include "internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
           
void* check_existing_listener(const char* interface_name, void* const connection, const enum ConnectionType connection_type, const bool loopback) {
    LOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);

    const uint32_t interface_len = strlen(interface_name);

    struct Listener* const existing_listener = hashmap_get(interface_name, interface_len, &listeners);

    if (existing_listener != NULL) {
        if (connection_type == CONNECTION_TYPE_CLIENT) {
            LOCK_ATOMIC_DATA_TYPE(&existing_listener->client_connections.atomic_lock);

            uint16_t* const restrict key_allocated_mem = allocator_allocate(&uint16_memory_allocator);
            *key_allocated_mem = ((struct SwiftNetClientConnection*)connection)->port_info.source_port;

            hashmap_insert(key_allocated_mem, sizeof(uint16_t), connection, &existing_listener->client_connections);

            UNLOCK_ATOMIC_DATA_TYPE(&existing_listener->client_connections.atomic_lock);
        } else {
            LOCK_ATOMIC_DATA_TYPE(&existing_listener->servers.atomic_lock);

            uint16_t* const restrict key_allocated_mem = allocator_allocate(&uint16_memory_allocator);
            *key_allocated_mem = ((struct SwiftNetServer*)connection)->server_port;

            hashmap_insert(key_allocated_mem, sizeof(uint16_t), connection, &existing_listener->servers);

            UNLOCK_ATOMIC_DATA_TYPE(&existing_listener->servers.atomic_lock);
        }

        UNLOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);

        return existing_listener;
    }

    struct Listener* const new_listener = allocator_allocate(&listener_memory_allocator);
    new_listener->servers = hashmap_create();
    new_listener->client_connections = hashmap_create();
    new_listener->pcap = swiftnet_pcap_open(interface_name);
    new_listener->addr_type = pcap_datalink(new_listener->pcap);
    memcpy(new_listener->interface_name, interface_name, interface_len + 1);
    new_listener->loopback = loopback;

    if (connection_type == CONNECTION_TYPE_CLIENT) {
        uint16_t* const restrict key_allocated_mem = allocator_allocate(&uint16_memory_allocator);
        *key_allocated_mem = ((struct SwiftNetClientConnection*)connection)->port_info.source_port;

        hashmap_insert(key_allocated_mem, sizeof(uint16_t), connection, &new_listener->client_connections);
    } else {
        uint16_t* const restrict key_allocated_mem = allocator_allocate(&uint16_memory_allocator);
        *key_allocated_mem = ((struct SwiftNetServer*)connection)->server_port;

        hashmap_insert(key_allocated_mem, sizeof(uint16_t), connection, &new_listener->servers);
    }

    char* const restrict listener_key = malloc(interface_len);

    memcpy(listener_key, interface_name, interface_len);

    hashmap_insert(listener_key, interface_len, new_listener, &listeners);

    UNLOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);

    pthread_create(&new_listener->listener_thread, NULL, interface_start_listening, new_listener);

    return new_listener;
}
