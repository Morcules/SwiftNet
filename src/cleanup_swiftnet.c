#include "internal/internal.h"
#include "internal/networking.h"
#include "swift_net.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

static inline void close_listeners() {
    LOCK_ATOMIC_DATA_TYPE(&listeners.atomic_lock);
    
    LOOP_HASHMAP(&listeners, struct Listener*,
        SWIFTNET_BREAK_RECEIVER_LOOP(&hashmap_data->network_data);

        WAIT_LISTENER_THREAD(hashmap_data);

        SWIFTNET_CLOSE_CONNECTION(&hashmap_data->network_data);

        hashmap_destroy(&hashmap_data->client_connections);
        hashmap_destroy(&hashmap_data->servers);
    )

    hashmap_destroy(&listeners);
}

static inline void close_background_service() {
    atomic_store_explicit(&swiftnet_closing, true, memory_order_release);

    pthread_join(memory_cleanup_thread, NULL);
}

void swiftnet_cleanup() {
    close_background_service();

    allocator_destroy(&packet_queue_node_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&packet_callback_queue_node_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&server_packet_data_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&client_packet_data_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&packet_buffer_memory_allocator ENABLE_INTERNAL_CHECK);
    
    #ifndef SWIFT_NET_DISABLE_REQUESTS
        allocator_destroy(&requests_sent_memory_allocator ENABLE_INTERNAL_CHECK);

        hashmap_destroy(&requests_sent);
    #endif

    close_listeners();

    allocator_destroy(&packet_sending_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&packet_completed_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&pending_message_memory_allocator ENABLE_INTERNAL_CHECK);

    
    allocator_destroy(&hashmap_item_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&server_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&client_connection_memory_allocator ENABLE_INTERNAL_CHECK);

    allocator_destroy(&listener_memory_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&uint16_memory_allocator DISABLE_INTERNAL_CHECK);
    allocator_destroy(&packet_completed_key_allocator DISABLE_INTERNAL_CHECK);
    allocator_destroy(&pending_message_key_allocator ENABLE_INTERNAL_CHECK);
    allocator_destroy(&packet_sending_key_allocator ENABLE_INTERNAL_CHECK);

    #ifdef SWIFT_NET_BACKEND_DPDK
    uint16_t port_id;
    uint16_t count;

    count = rte_eth_dev_count_avail();

    for (port_id = 0; port_id < count; port_id++) {
        if (!rte_eth_dev_is_valid_port(port_id))
            continue;

        rte_eth_dev_close(port_id);
    }

    rte_eal_cleanup();
    #endif

    #ifndef SWIFT_NET_DISABLE_REQUESTS
    allocator_destroy(&request_sent_key_allocator DISABLE_INTERNAL_CHECK);
    #endif

    #ifdef SWIFT_NET_INTERNAL_TESTING
    printf("Bytes leaked: %d\nItems leaked: %d\n", bytes_leaked, items_leaked);
    #endif
}
