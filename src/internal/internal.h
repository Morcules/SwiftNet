#pragma once

#include <arpa/inet.h>
#include <pcap/pcap.h>
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

#ifdef __APPLE__
    #include <sys/_endian.h>
#elif __linux__
    #include <endian.h>
#endif

#ifdef __linux__
#define LOOPBACK_INTERFACE_NAME "lo\0"
#elif defined(__APPLE__)
#define LOOPBACK_INTERFACE_NAME "lo0\0"
#endif

#ifdef SWIFT_NET_INTERNAL_TESTING
    #define ENABLE_INTERNAL_CHECK , 0
    #define DISABLE_INTERNAL_CHECK , 1
#else
    #define ENABLE_INTERNAL_CHECK
    #define DISABLE_INTERNAL_CHECK
#endif

#define SWIFTNET_PCAP_SEND_SAFE(pcap, buffer, len) \
    while(swiftnet_pcap_send(pcap, buffer, len) == -2) { \
        usleep(2000); \
    } \

enum RequestLostPacketsReturnType {
    REQUEST_LOST_PACKETS_RETURN_UPDATED_BIT_ARRAY = 0x00,
    REQUEST_LOST_PACKETS_RETURN_COMPLETED_PACKET  = 0x01
};

// in body use variables "hashmap_item" and "hashmap_data"
// "hashmap_item" contains pointer to current struct SwiftNetHashMapItem 
// "hashmap_data" contains data stored inside struct SwiftNetHashMapItem
#define LOOP_HASHMAP(hashmap, loop_body) \
    for(uint32_t i = 0; i < ((hashmap)->capacity + 31) / 32; i++) { \
        uint32_t current_index = *((hashmap)->item_occupation + i); \
        if(current_index == 0x00) { \
            continue; \
        } \
        uint32_t inverted = ~(current_index); \
        while(inverted != UINT32_MAX) { \
            uint32_t bit_index = __builtin_ctz(inverted); \
            inverted |= 1 << bit_index; \
            for(struct SwiftNetHashMapItem* hashmap_item = (hashmap)->items + ((i * 32) + bit_index); hashmap_item != NULL; hashmap_item = hashmap_item->next) { \
                void* const hashmap_data = hashmap_item->value; \
                loop_body \
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
#define PACKET_PREPEND_SIZE(addr_type) ((addr_type == DLT_NULL) ? sizeof(uint32_t) : addr_type == DLT_EN10MB ? sizeof(struct ether_header) : 0)
#define PACKET_HEADER_SIZE (sizeof(struct ip) + sizeof(struct SwiftNetPacketInfo))
#define HANDLE_PACKET_CONSTRUCTION(ip_header, packet_info, addr_type, eth_hdr, buffer_size, buffer_name) \
    uint8_t buffer_name[buffer_size]; \
    if(addr_type == DLT_NULL) { \
        uint32_t family = PF_INET; \
        memcpy(buffer_name, &family, sizeof(family)); \
        memcpy(buffer_name + sizeof(family), ip_header, sizeof(*ip_header)); \
        memcpy(buffer_name + sizeof(family) + sizeof(*ip_header), packet_info, sizeof(*packet_info)); \
    } else if(addr_type == DLT_EN10MB){ \
        memcpy(buffer_name, eth_hdr, sizeof(*eth_hdr)); \
        memcpy(buffer_name + sizeof(*eth_hdr), ip_header, sizeof(*ip_header)); \
        memcpy(buffer_name + sizeof(*eth_hdr) + sizeof(*ip_header), packet_info, sizeof(*packet_info)); \
    } \

// Simple crc16 call with proper memory order
#define HANDLE_CHECKSUM(buffer, size, prepend_size) \
    const uint32_t checksum = crc32(buffer, size); \
    memcpy(buffer + prepend_size + sizeof(struct ip) + offsetof(struct SwiftNetPacketInfo, checksum), &checksum, sizeof(checksum));

#define DEFAULT_MAC_ADDRESS_STRUCT {.ether_dhost = {0xff,0xff,0xff,0xff,0xff,0xff}, .ether_type = htons(0x0800)}

// Number used in ip.proto
#define PROT_NUMBER 253

// Size of struct field
#define SIZEOF_FIELD(type, field) sizeof(((type *)0)->field)

// How many seconds between each memory cleanup.
#define PACKET_HISTORY_STORE_TIME 5

#define PRINT_ERROR(fmt, ...) \
    do { fprintf(stderr, fmt " | function: %s | line: %d\n", ##__VA_ARGS__, __FUNCTION__, __LINE__); } while (0)

#define MIN(one, two) (one > two ? two : one)

static inline void* swiftnet_allocate_memory(const uint32_t size) {
    // Future
    return NULL;
}

static inline void swiftnet_free_memory(const uint32_t size, const void* restrict const ptr) {
    // Future
    return;
}

static inline void swiftnet_reallocate_memory(const uint32_t new_size, const void* restrict const ptr) {
    // Future
    return;
}

static inline uint32_t crc32(const uint8_t* const data, const uint32_t length) {
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

struct Listener {
    pcap_t* pcap;
    pthread_t listener_thread;
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

extern pthread_t memory_cleanup_thread;
extern _Atomic bool swiftnet_closing;

extern void* memory_cleanup_background_service();

extern int get_default_interface_and_mac(char* restrict interface_name, const uint32_t interface_name_length, uint8_t* restrict mac_out, const int sockfd);
extern const uint32_t get_mtu(const char* restrict const interface, const int sockfd);
extern int get_bpf_device();
extern int bind_bpf_to_interface(const int bpf, const bool loopback);
extern int setup_bpf_settings(const int bpf);

extern void* swiftnet_server_process_packets(void* const void_server);
extern void* swiftnet_client_process_packets(void* const void_client);

extern void* execute_packet_callback_client(void* const void_client);
extern void* execute_packet_callback_server(void* const void_server);

extern struct in_addr private_ip_address;
extern uint8_t mac_address[6];
extern char default_network_interface[SIZEOF_FIELD(struct ifreq, ifr_name)];
extern pcap_t* swiftnet_pcap_open(const char* restrict const interface);
extern int swiftnet_pcap_send(pcap_t* const pcap, const uint8_t* restrict const data, const int len);

extern void* check_existing_listener(const char* restrict const interface_name, void* const connection, const enum ConnectionType connection_type, const bool loopback);

#ifdef SWIFT_NET_INTERNAL_TESTING
extern uint32_t bytes_leaked;
extern uint32_t items_leaked;
#endif

#ifdef SWIFT_NET_DEBUG
extern struct SwiftNetDebugger debugger;

static inline bool check_debug_flag(const SwiftNetDebugFlags flag) {
    return (debugger.flags & flag) != 0;
}

static inline void send_debug_message(const char* restrict const message, ...) {
    va_list args;
    char* prefix;
    uint32_t prefix_length;
    uint32_t message_length;


    va_start(args, message);

    prefix = "[DEBUG] ";

    prefix_length = strlen(prefix);
    message_length = strlen(message);

    char full_message[prefix_length + message_length + 1];

    memcpy(full_message, prefix, prefix_length);
    memcpy(full_message + prefix_length, message, message_length);
    full_message[prefix_length + message_length] = '\0';

    vprintf(full_message, args);

    va_end(args);
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

extern void* interface_start_listening(void* const listener_void);

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

#ifdef SWIFT_NET_REQUESTS
struct RequestSent {
    _Atomic(void*) packet_data;
    struct in_addr address;
    uint16_t packet_id;
};

extern struct SwiftNetMemoryAllocator requests_sent_memory_allocator;
extern struct SwiftNetHashMap requests_sent;
#endif

extern void swiftnet_send_packet(
    const void* const connection,
    const uint32_t target_maximum_transmission_unit,
    const struct SwiftNetPortInfo port_info,
    const struct SwiftNetPacketBuffer* const packet,
    const uint32_t packet_length,
    const struct in_addr* const target_addr,
    struct SwiftNetHashMap* const packets_sending,
    struct SwiftNetMemoryAllocator* const packets_sending_memory_allocator,
    pcap_t* const pcap,
    const struct ether_header eth_hdr,
    const bool loopback,
    const uint16_t addr_type,
    const uint8_t prepend_size
    #ifdef SWIFT_NET_REQUESTS
    , struct RequestSent* const request_sent
    , const bool response
    , const uint16_t request_packet_id
    #endif
);

static inline struct SwiftNetPacketInfo construct_packet_info(const uint32_t packet_length, const uint8_t packet_type, const uint32_t chunk_amount, const uint32_t chunk_index, const struct SwiftNetPortInfo port_info) {
    return (struct SwiftNetPacketInfo){
        .packet_length = packet_length,
        .packet_type = packet_type,
        .chunk_amount = chunk_amount,
        .chunk_index = chunk_index,
        .maximum_transmission_unit = maximum_transmission_unit,
        .port_info = port_info,
        .checksum = 0x00
    };
}

static struct ip construct_ip_header(const struct in_addr destination_addr, const uint32_t packet_size, const uint16_t packet_id) {
    struct ip ip_header;


    ip_header = (struct ip){
        .ip_v = 4,
        .ip_hl = 5,
        .ip_tos = 0,
        .ip_p = PROT_NUMBER,
        .ip_len = htons(packet_size),
        .ip_id = htons(packet_id),
        .ip_off = htons(0),
        .ip_ttl = 64,
        .ip_sum = htons(0),
        .ip_src = private_ip_address,
        .ip_dst = destination_addr
    };

    return ip_header;
}
