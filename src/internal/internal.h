#pragma once

#include <arpa/inet.h>
#include <stdint.h>
#include <arm_acle.h>
#include <string.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <stdio.h>
#include <net/if.h>
#include "../swift_net.h"

#ifdef __SANITIZE_ADDRESS__
#include <sanitizer/asan_interface.h>
    #define ASAN_UNPOISON(addr, size) __asan_unpoison_memory_region((addr), (size))
    #define ASAN_POISON(addr, size)   __asan_poison_memory_region((addr), (size))
#else
    #define ASAN_UNPOISON(addr, size) ((void)(addr), (void)(size))
    #define ASAN_POISON(addr, size)   ((void)(addr), (void)(size))
#endif

#define IS_NET_MESSAGE(packet_type) (packet_type >= REQUEST_INFORMATION)

#ifdef __APPLE__
    #include <sys/_endian.h>
#elif __linux__
    #include <endian.h>
#endif

#define STRINGIFY(...) #__VA_ARGS__
#define TOSTRING(...) STRINGIFY(__VA_ARGS__)

#define ASSUME(cond) __builtin_assume(cond)
#define ALWAYS_INLINE __attribute__((always_inline))
#define MAYBE_UNUSED [[maybe_unused]]

#ifdef SWIFT_NET_BACKEND_PCAP
    #define PCAP_ONLY
    #define DPDK_ONLY MAYBE_UNUSED
#elif defined(SWIFT_NET_BACKEND_DPDK)
    #define PCAP_ONLY MAYBE_UNUSED
    #define DPDK_ONLY
#endif

#ifdef SWIFT_NET_BACKEND_DPDK
extern uint32_t lcores_used[];
#endif

#ifdef SWIFT_NET_BACKEND_PCAP
#ifdef __linux__
#define CLIENT_LOOPBACK_INTERFACE_NAME "lo\0"
#define SERVER_LOOPBACK_INTERFACE_NAME "lo\0"
#elif defined(__APPLE__)
#define CLIENT_LOOPBACK_INTERFACE_NAME "lo0\0"
#define SERVER_LOOPBACK_INTERFACE_NAME "lo0\0"
#endif
#elif defined(SWIFT_NET_BACKEND_DPDK)
#define CLIENT_LOOPBACK_INTERFACE_NAME "net_ring0\0"
#define SERVER_LOOPBACK_INTERFACE_NAME "net_ring0\0"
#endif

#ifdef SWIFT_NET_INTERNAL_TESTING
    #define ENABLE_INTERNAL_CHECK , 0
    //#define DISABLE_INTERNAL_CHECK , 1
    #define DISABLE_INTERNAL_CHECK , 0
#else
    #define ENABLE_INTERNAL_CHECK
    #define DISABLE_INTERNAL_CHECK
#endif

enum RequestLostPacketsReturnType {
    REQUEST_LOST_PACKETS_RETURN_UPDATED_BIT_ARRAY = 0x00,
    REQUEST_LOST_PACKETS_RETURN_COMPLETED_PACKET  = 0x01
};

struct ReceiverPacketData {
    const uint8_t* const data;
    DPDK_ONLY struct rte_mbuf* dpdk_buf;
    uint32_t data_len;
};

// in body use variables "hashmap_item" and "hashmap_data"
// "hashmap_item" contains pointer to current struct SwiftNetHashMapItem 
// "hashmap_data" contains data stored inside struct SwiftNetHashMapItem
#define LOOP_HASHMAP(hashmap, data_cast, loop_body) \
    for(uint32_t i = 0; i < ((hashmap)->capacity + 31) / 32; i++) { \
        uint32_t current_index = *((hashmap)->item_occupation + i); \
        printf("index: %d\n", current_index); \
        while(current_index != 0) { \
            uint32_t bit_index = (uint32_t)(__builtin_ctz(current_index)); \
            void* next_value; \
            current_index &= ~(1 << bit_index); \
            for(struct SwiftNetHashMapItem* hashmap_item = (hashmap)->items + ((i * 32) + bit_index); hashmap_item != NULL; ) { \
                if(hashmap_item->next != NULL) { \
                    next_value = hashmap_item->next->value; \
                } else { next_value = NULL; } \
                MAYBE_UNUSED data_cast const hashmap_data = hashmap_item->value; \
                loop_body \
                if(hashmap_item->value == NULL) {break;} else { \
                    if(hashmap_item->value == next_value) { \
                        continue; \
                    } else { \
                        hashmap_item = hashmap_item->next; \
                        continue; \
                    } \
                } \
            } \
        } \
    }

#define LOCK_ATOMIC_DATA_TYPE(atomic_field) \
    do { \
        bool locked = false; \
        while(!atomic_compare_exchange_strong_explicit(atomic_field, &locked, true, memory_order_acquire, memory_order_relaxed)) { \
            locked = false; \
        } \
    } while(0);

#define UNLOCK_ATOMIC_DATA_TYPE(atomic_field) \
    atomic_store_explicit(atomic_field, false, memory_order_release);

// Size of memory allocated before ip header.
// Memory should contain either an eth hdr or any specific data depending on addr type (loopback or real interface)
#ifdef SWIFT_NET_BACKEND_DPDK
#define PACKET_PREPEND_SIZE(addr_type) sizeof(struct ether_header)
#elif defined(SWIFT_NET_BACKEND_PCAP)
#define PACKET_PREPEND_SIZE(addr_type) ((addr_type == DLT_NULL) ? (uint8_t)sizeof(uint32_t) : addr_type == DLT_EN10MB ? (uint8_t)sizeof(struct ether_header) : (uint8_t)0)
#endif
#define PACKET_HEADER_SIZE (sizeof(struct ip) + sizeof(struct SwiftNetChunkMetadata))

#define DEFAULT_MAC_ADDRESS_STRUCT (struct ether_header){.ether_dhost = {0xff,0xff,0xff,0xff,0xff,0xff}, .ether_type = htons(0x0800)}

// Number used in ip.proto
#define PROT_NUMBER 253

// Size of struct field
#define SIZEOF_FIELD(type, field) sizeof(((type *)0)->field)

// How many seconds between each memory cleanup.
#define PACKET_HISTORY_STORE_TIME 5

#define PRINT_ERROR(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, " | function: %s | line: %d\n", __func__, __LINE__); \
    } while (0)

#define MIN(one, two) (one > two ? two : one)

/*
inline void* swiftnet_allocate_memory(const uint32_t size) {
    // Future
    return NULL;
}

inline void swiftnet_free_memory(const uint32_t size, const void* restrict const ptr) {
    // Future
    return;
}

inline void swiftnet_reallocate_memory(const uint32_t new_size, const void* restrict const ptr) {
    // Future
    return;
}
*/

static inline ALWAYS_INLINE uint32_t calculate_chunk_amount(const uint32_t packet_length, const uint32_t mtu) {
    const uint32_t first_packet_len = mtu - PACKET_HEADER_SIZE - sizeof(struct SwiftNetPacketMetadata);

    return packet_length > first_packet_len ? ((packet_length - (mtu - PACKET_HEADER_SIZE - sizeof(struct SwiftNetPacketMetadata)) - 1) / (mtu - PACKET_HEADER_SIZE)) + 2 : 1;
}

static inline ALWAYS_INLINE uint32_t crc32(const uint8_t* const data, const uint32_t length) {
    const uint8_t* ptr = data;
    uint32_t remaining = length;
    uint32_t crc = 0xFFFFFFFF;
    
    while (remaining >= 8) {
        crc = __crc32d(crc, *(const uint64_t*)ptr);
        ptr += 8;
        remaining -= 8;
    }

    while (remaining > 0) {
        crc = __crc32b(crc, *ptr);
        ptr++;
        remaining--;
    }

    return ~crc;
}

enum StackCreatingState {
    STACK_CREATING_LOCKED = 0,
    STACK_CREATING_UNLOCKED = 1
};

struct PendingMessagesKey {
    uint16_t source_port;
    uint16_t packet_id;
};

struct PacketCompletedKey {
    uint16_t source_port;
    uint16_t packet_id;
};

struct RequestSentKey {
    uint16_t packet_id;
};

struct PacketSendingKey {
    uint16_t packet_id;
};

struct Listener {
    struct SwiftNetNetworkData network_data;
    #ifdef SWIFT_NET_BACKEND_PCAP
    pthread_t listener_thread;
    #elif defined(SWIFT_NET_BACKEND_DPDK)
    uint32_t lcore;
    uint16_t lcore_internal_index;
    #endif
    struct SwiftNetHashMap servers;
    struct SwiftNetHashMap client_connections;
    char interface_name[IFNAMSIZ];
    uint16_t addr_type;
    bool loopback;
};

enum ConnectionType {
    CONNECTION_TYPE_SERVER,
    CONNECTION_TYPE_CLIENT
};

extern uint64_t seed;

extern struct SwiftNetHashMap listeners;

extern struct SwiftNetMemoryAllocator pending_message_key_allocator;
extern struct SwiftNetMemoryAllocator packet_completed_key_allocator;

#ifndef SWIFT_NET_DISABLE_REQUESTS
extern struct SwiftNetMemoryAllocator request_sent_key_allocator;
#endif
extern struct SwiftNetMemoryAllocator packet_sending_key_allocator;

extern pthread_t memory_cleanup_thread;
extern _Atomic bool swiftnet_closing;

extern void* memory_cleanup_background_service(void* user);

extern int get_default_interface_and_mac(char* restrict interface_name, const uint32_t interface_name_length, uint8_t* restrict mac_out, const int sockfd);
extern uint16_t get_mtu(const char* restrict const interface, const int sockfd);

extern void* swiftnet_server_process_packets(void* const void_server);
extern void* swiftnet_client_process_packets(void* const void_client);

extern void* execute_packet_callback_client(void* const void_client);
extern void* execute_packet_callback_server(void* const void_server);

extern struct in_addr private_ip_address;
extern uint8_t mac_address[6];
extern char default_network_interface[SIZEOF_FIELD(struct ifreq, ifr_name)];

extern void* check_existing_listener(const char* restrict const interface_name, void* const connection, const enum ConnectionType connection_type, const bool loopback);

#ifdef SWIFT_NET_INTERNAL_TESTING
extern uint32_t bytes_leaked;
extern uint32_t items_leaked;
#endif

#ifndef SWIFT_NET_DISABLE_DEBUGGING
extern struct SwiftNetDebugger debugger;

static inline ALWAYS_INLINE bool check_debug_flag(const SwiftNetDebugFlags flag) {
    return (debugger.flags & flag) != 0;
}

MAYBE_UNUSED __attribute__((format(printf, 1, 2))) static inline ALWAYS_INLINE void send_debug_message(const char *restrict const message, ...) {
    va_list args;

    va_start(args, message);

    printf("[DEBUG] ");
    vprintf(message, args);

    va_end(args);
}
#else
static inline ALWAYS_INLINE bool check_debug_flag(MAYBE_UNUSED const SwiftNetDebugFlags flag) {
    return true;
}

MAYBE_UNUSED __attribute__((format(printf, 1, 2))) static inline ALWAYS_INLINE void send_debug_message(MAYBE_UNUSED const char *restrict const message, ...) {

}
#endif

#define STACK_CREATING_LOCKED 0
#define STACK_CREATING_UNLOCKED 1

#define ALLOCATOR_STACK_OCCUPIED 1
#define ALLOCATOR_STACK_FREE 0

extern uint32_t semaphore_counter;

extern struct SwiftNetMemoryAllocator uint16_memory_allocator;

extern struct SwiftNetMemoryAllocator allocator_create(const uint32_t item_size, const uint32_t chunk_item_amount);
extern void* allocator_allocate(struct SwiftNetMemoryAllocator* const memory_allocator);
extern void allocator_free(struct SwiftNetMemoryAllocator* const memory_allocator, void* const memory_location);
extern void allocator_destroy(struct SwiftNetMemoryAllocator* const memory_allocator
    #ifdef SWIFT_NET_INTERNAL_TESTING
        , const bool disable_internal_check
    #endif
);

extern struct SwiftNetMemoryAllocator packet_queue_node_memory_allocator;
extern struct SwiftNetMemoryAllocator packet_callback_queue_node_memory_allocator;
extern struct SwiftNetMemoryAllocator server_packet_data_memory_allocator;
extern struct SwiftNetMemoryAllocator client_packet_data_memory_allocator;
extern struct SwiftNetMemoryAllocator packet_buffer_memory_allocator;
extern struct SwiftNetMemoryAllocator server_memory_allocator;
extern struct SwiftNetMemoryAllocator client_connection_memory_allocator;
extern struct SwiftNetMemoryAllocator listener_memory_allocator;
extern struct SwiftNetMemoryAllocator hashmap_item_memory_allocator;
extern struct SwiftNetMemoryAllocator pending_message_memory_allocator;
extern struct SwiftNetMemoryAllocator packet_completed_memory_allocator;
extern struct SwiftNetMemoryAllocator packet_sending_memory_allocator;

extern void* interface_start_listening_pcap(void* const listener_void);
extern int interface_start_listening_dpdk(void* const listener_void);

extern void* vector_get(struct SwiftNetVector* const vector, const uint32_t index);
extern void vector_remove(struct SwiftNetVector* const vector, const uint32_t index);
extern void vector_push(struct SwiftNetVector* const vector, void* const data);
extern void vector_destroy(struct SwiftNetVector* const vector);
extern struct SwiftNetVector vector_create(const uint32_t starting_amount);

extern struct SwiftNetHashMap hashmap_create(struct SwiftNetMemoryAllocator* const key_memory_allocator);
extern void hashmap_insert(void* const key_data, const uint32_t data_size, void* const value, struct SwiftNetHashMap* const hashmap);
extern void hashmap_remove(void* const key_data, const uint32_t data_size, struct SwiftNetHashMap* const hashmap);
extern void hashmap_destroy(struct SwiftNetHashMap* const hashmap);
extern void* hashmap_get(const void* const key_data, const uint32_t data_size, struct SwiftNetHashMap* const hashmap);

extern void* server_start_pcap(void* const server_void);
extern void* client_start_pcap(void* const client_void);

#ifndef SWIFT_NET_DISABLE_REQUESTS
struct RequestSent {
    _Atomic(void*) packet_data;
    struct in_addr address;
    uint16_t packet_id;
};

extern struct SwiftNetMemoryAllocator requests_sent_memory_allocator;
extern struct SwiftNetHashMap requests_sent;
#endif

extern uint16_t maximum_transmission_unit;

extern void swiftnet_send_packet(
    const uint16_t target_maximum_transmission_unit,
    const struct SwiftNetPortInfo port_info,
    const struct SwiftNetPacketBuffer* const packet,
    const uint32_t packet_length,
    const struct in_addr* const target_addr,
    struct SwiftNetHashMap* const packets_sending,
    const struct ether_header eth_hdr,
    const struct SwiftNetNetworkData network_data
    #ifndef SWIFT_NET_DISABLE_REQUESTS
    , struct RequestSent* const request_sent
    , const bool response
    , const uint16_t request_packet_id
    #endif
);

static inline ALWAYS_INLINE struct SwiftNetChunkMetadata construct_chunk_metadata(const uint8_t packet_type, const uint32_t chunk_index, const struct SwiftNetPortInfo port_info) {
    return (struct SwiftNetChunkMetadata){
        .chunk_index = chunk_index,
        .checksum = 0x00,
        .port_info = port_info,
        .packet_type = packet_type
    };
}

static inline ALWAYS_INLINE struct SwiftNetPacketMetadata construct_packet_metadata(const uint32_t packet_length, const uint32_t chunk_amount) {
    return (struct SwiftNetPacketMetadata){
        .packet_length = packet_length,
        .chunk_amount = chunk_amount,
        .maximum_transmission_unit = maximum_transmission_unit
    };
}

static inline ALWAYS_INLINE struct ip construct_ip_header(const struct in_addr destination_addr, const uint16_t packet_size, const uint16_t packet_id) {
    struct ip ip_header;


    ip_header = (struct ip){
        .ip_hl = 5,
        .ip_v = 4,
        .ip_tos = 0,
        .ip_len = htons(packet_size),
        .ip_id = htons(packet_id),
        .ip_off = htons(0),
        .ip_ttl = 64,
        .ip_p = PROT_NUMBER,
        .ip_sum = htons(0),
        .ip_src = private_ip_address,
        .ip_dst = destination_addr
    };

    return ip_header;
}
