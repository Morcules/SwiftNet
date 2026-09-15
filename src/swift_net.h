#pragma once

#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <semaphore.h>
#include <netinet/ip.h>
#include <stdbool.h>

//#define SWIFT_NET_BACKEND_PCAP

#ifdef SWIFT_NET_BACKEND_PCAP
#include <pcap/pcap.h>
#endif

#ifdef SWIFT_NET_BACKEND_DPDK
#include <rte_mbuf.h>

#define DPDK_BURST_SIZE 32
#endif

#ifdef __cplusplus
extern "C" {

#define restrict __restrict__
#endif

#define SWIFT_NET_ALIGNED(bytes) __attribute__((aligned(bytes)))
#define SWIFT_NET_PACKED __attribute__((packed))

// Multiplication of memory pre allocated.
// More memory = better performance
#ifndef SWIFT_NET_MEMORY_USAGE
#define SWIFT_NET_MEMORY_USAGE 5
#endif

struct SwiftNetNetworkData {
    #ifdef SWIFT_NET_BACKEND_DPDK
    struct rte_mempool* mem_pool;
    uint16_t port;
    uint16_t addr_type;
    uint8_t prepend_size;
    _Atomic bool closing;
    #endif
    #ifdef SWIFT_NET_BACKEND_PCAP
    pcap_t* pcap;
    uint16_t addr_type;
    uint8_t prepend_size;
    #endif
} SWIFT_NET_ALIGNED(8);

enum PacketType : uint8_t {
    MESSAGE = 0x01,
    #ifndef SWIFT_NET_DISABLE_REQUESTS
    REQUEST = 0x02,
    RESPONSE = 0x03,
    #endif
    REQUEST_INFORMATION = 0x04,
    SEND_LOST_PACKETS_REQUEST = 0x05,
    SEND_LOST_PACKETS_RESPONSE = 0x06,
    SUCCESSFULLY_RECEIVED_PACKET = 0x07,   
    #ifndef DISABLE_DYNAMIC_RATE_LIMITING 
    PACKET_DELAY_UPDATE = 0x08,
    #endif
};

#ifndef DISABLE_DYNAMIC_RATE_LIMITING
enum SwiftNetPacketDelayUpdateStatus : uint8_t {
    LOWER_DELAY,
    INCREASE_DELAY
};
#endif

#define PACKET_INFO_ID_NONE UINT16_C(0xFFFF)

#ifndef likely
#define unlikely(x) __builtin_expect((x), 0x00)
#define likely(x) __builtin_expect((x), 0x01)
#endif

#define SWIFTNET_DEBUG_FLAGS(num) ((SwiftNetDebugFlags)(num))

typedef uint8_t SwiftNetDebugFlags;

#define SWIFTNET_DEBUG_PACKETS_SENDING   (1u << 1)
#define SWIFTNET_DEBUG_PACKETS_RECEIVING (1u << 2)
#define SWIFTNET_DEBUG_INITIALIZATION    (1u << 3)
#define SWIFTNET_DEBUG_LOST_PACKETS      (1u << 4)

struct SwiftNetDebugger {
    int flags;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetPortInfo {
    uint16_t destination_port;
    uint16_t source_port;
} SWIFT_NET_ALIGNED(4);

struct SwiftNetClientAddrData {
    uint16_t maximum_transmission_unit;
    struct in_addr sender_address;   
    uint16_t port;
    uint8_t mac_address[6];
} SWIFT_NET_ALIGNED(4);

struct SwiftNetPacketClientMetadata {
    uint32_t data_length;
    struct SwiftNetPortInfo port_info;
    uint16_t packet_id;
    #ifndef SWIFT_NET_DISABLE_REQUESTS
    bool expecting_response;
    #endif
} SWIFT_NET_ALIGNED(4);

struct SwiftNetPacketMetadata {
    uint32_t packet_length;
    uint32_t chunk_amount;
    uint16_t maximum_transmission_unit;
} SWIFT_NET_PACKED;

struct SwiftNetChunkMetadata {
    uint32_t chunk_index;
    uint32_t checksum;
    struct SwiftNetPortInfo port_info;
    uint8_t packet_type;
} SWIFT_NET_PACKED;

struct SwiftNetPendingMessageCache {
    struct SwiftNetPacketQueueNode* cache[0xFF];
    uint32_t cache_size;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetPendingMessage {
    struct SwiftNetPendingMessageCache cache;
    struct SwiftNetPacketMetadata packet_metadata;
    uint8_t* chunks_received;
    uint8_t* packet_data_start;
    uint32_t chunks_received_length;
    uint32_t chunks_received_number;
    #ifndef DISABLE_DYNAMIC_RATE_LIMITING
    uint32_t last_index_checked;
    uint32_t last_chunks_received_number;
    #endif
    uint16_t source_port;
    uint16_t packet_id;
    bool sending_lost_packets;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetPacketServerMetadata {
    struct SwiftNetClientAddrData sender;
    uint32_t data_length;
    struct SwiftNetPortInfo port_info;
    uint16_t packet_id;
    #ifndef SWIFT_NET_DISABLE_REQUESTS
    bool expecting_response;
    #endif
} SWIFT_NET_ALIGNED(4);

struct SwiftNetServerInformation {
    uint16_t maximum_transmission_unit;
} SWIFT_NET_ALIGNED(4);

enum SwiftNetPacketSendingUpdated : uint8_t {
    NO_UPDATE,
    UPDATED_LOST_CHUNKS,
    SUCCESSFULLY_RECEIVED
};

struct SwiftNetPacketSending {
    uint32_t* lost_chunks;
    _Atomic enum SwiftNetPacketSendingUpdated updated;
    #ifndef DISABLE_DYNAMIC_RATE_LIMITING
    _Atomic uint32_t current_send_delay;
    #endif
    uint32_t lost_chunks_size;
    uint16_t packet_id;
    _Atomic bool locked;
} SWIFT_NET_ALIGNED(4);

struct SwiftNetPacketCompleted {
    uint16_t packet_id;
    bool marked_cleanup;
} SWIFT_NET_ALIGNED(4);

struct SwiftNetPacketBuffer {
    #ifdef SWIFT_NET_BACKEND_DPDK
    struct rte_mbuf** dpdk_buffers;
    uint32_t total_data_size; // Only counting data stored not eth, ip headers or packet info
    uint32_t buf_amount;
    uint16_t data_len_per_packet;
    uint32_t append_offset;
    #elif defined(SWIFT_NET_BACKEND_PCAP)
    uint8_t* packet_buffer_start;   // Start of the allocated buffer
    uint8_t* packet_data_start;     // Start of the stored data
    uint8_t* packet_append_pointer; // Current position to append new data
    #endif
} SWIFT_NET_ALIGNED(8);

struct SwiftNetPacketQueueNode {
    struct SwiftNetPacketQueueNode* next;
    uint8_t* data;
    uint32_t data_read;
    struct in_addr sender_address;   
} SWIFT_NET_ALIGNED(8);

struct SwiftNetPacketQueue {
    struct SwiftNetPacketQueueNode* first_node;
    struct SwiftNetPacketQueueNode* last_node;
    _Atomic bool locked;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetPacketCallbackQueueNode {
    struct SwiftNetPendingMessage* pending_message;
    struct SwiftNetPacketCallbackQueueNode* next;
    void* packet_data;
    uint16_t packet_id;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetServerPacketData {
    struct SwiftNetPendingMessage* internal_pending_message; // Do not use!!
    uint8_t* data;
    uint8_t* buffer_start;
    uint8_t* current_pointer;
    struct SwiftNetPacketServerMetadata metadata;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetClientPacketData {
    struct SwiftNetPendingMessage* internal_pending_message; // Do not use!!
    uint8_t* data;
    uint8_t* buffer_start;
    uint8_t* current_pointer;
    struct SwiftNetPacketClientMetadata metadata;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetPacketCallbackQueue {
    struct SwiftNetPacketCallbackQueueNode* first_node;
    struct SwiftNetPacketCallbackQueueNode* last_node;
    _Atomic bool locked;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetSentSuccessfullyCompletedPacketSignal {
    uint16_t packet_id;
    bool confirmed;
} SWIFT_NET_ALIGNED(4);

struct SwiftNetMemoryAllocatorStack {
    void* pointers;
    void* data;
    #ifdef SWIFT_NET_INTERNAL_TESTING 
    uint8_t* ptr_status;
    #endif
    _Atomic uint32_t size;
    uint16_t index;
    #ifdef SWIFT_NET_INTERNAL_TESTING 
    _Atomic bool accessing_ptr_status;
    #endif
} SWIFT_NET_ALIGNED(8);

struct SwiftNetChunkStorageManager {
    _Atomic(void*) first_item;
    _Atomic(void*) last_item;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetMemoryAllocator {
    _Atomic uint64_t occupied;
    _Atomic(struct SwiftNetMemoryAllocatorStack*) stacks[64];
    _Atomic uint16_t stacks_allocated;
    uint32_t item_size;
    uint32_t chunk_item_amount;
    _Atomic uint8_t creating_stack;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetVector {
    void** data;
    uint32_t size;
    uint32_t capacity;
    _Atomic bool locked;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetHashMapItem {
    struct SwiftNetHashMapItem* next; // Contains next element with same key.
    void* key_original_data; // Dynamically allocated original key data
    void* value; // Data stored in item
    uint32_t key_original_data_size;
} SWIFT_NET_ALIGNED(8);

// Custom implementation of a hashmap
struct SwiftNetHashMap {
    struct SwiftNetHashMapItem* items;
    struct SwiftNetMemoryAllocator* key_memory_allocator;
    uint32_t* item_occupation; // Bitset tracking which indexes of items array are occupied for looping through items without many cycles.
    uint32_t capacity;
    uint32_t size;
    _Atomic bool atomic_lock;
} SWIFT_NET_ALIGNED(8);

// Connection data
struct SwiftNetClientConnection {
    struct SwiftNetHashMap packets_completed;
    struct SwiftNetHashMap pending_messages;
    struct SwiftNetHashMap packets_sending;
    struct SwiftNetMemoryAllocator packets_completed_memory_allocator;
    struct SwiftNetMemoryAllocator pending_messages_memory_allocator;
    struct SwiftNetMemoryAllocator packets_sending_memory_allocator;
    struct SwiftNetNetworkData network_data;
    struct SwiftNetPacketQueue packet_queue;
    struct SwiftNetPacketCallbackQueue packet_callback_queue;
    _Atomic(void (*)(struct SwiftNetClientPacketData* const, void* const user)) packet_handler;
    _Atomic(void*) packet_handler_user_arg;
    pthread_mutex_t process_packets_mtx;
    pthread_mutex_t execute_callback_mtx;
    pthread_cond_t process_packets_cond;
    pthread_cond_t execute_callback_cond;
    pthread_t process_packets_thread;
    pthread_t execute_callback_thread;
    struct SwiftNetPortInfo port_info;
    struct ether_header eth_header; 
    uint16_t maximum_transmission_unit;
    struct in_addr server_addr;
    bool loopback;
    _Atomic bool processing_packets;
    _Atomic bool executing_packets;
    _Atomic bool closing;
    _Atomic bool initialized;
} SWIFT_NET_ALIGNED(8);

struct SwiftNetServer {
    struct SwiftNetHashMap packets_completed;
    struct SwiftNetHashMap pending_messages;
    struct SwiftNetHashMap packets_sending;
    struct SwiftNetMemoryAllocator packets_completed_memory_allocator;
    struct SwiftNetMemoryAllocator pending_messages_memory_allocator;
    struct SwiftNetMemoryAllocator packets_sending_memory_allocator;
    struct SwiftNetNetworkData network_data;
    struct SwiftNetPacketQueue packet_queue;
    struct SwiftNetPacketCallbackQueue packet_callback_queue;
    _Atomic(void (*)(struct SwiftNetServerPacketData* const, void* const user)) packet_handler;
    _Atomic(void*) packet_handler_user_arg;
    pthread_mutex_t process_packets_mtx;
    pthread_mutex_t execute_callback_mtx;
    pthread_cond_t process_packets_cond;
    pthread_cond_t execute_callback_cond;
    pthread_t process_packets_thread;
    pthread_t execute_callback_thread;
    struct ether_header eth_header; 
    uint16_t server_port;        
    bool loopback;
    _Atomic bool processing_packets;
    _Atomic bool executing_packets;
    _Atomic bool closing;
} SWIFT_NET_ALIGNED(8);

// Set a custom message (packet) handler for the server.
extern void swiftnet_server_set_message_handler(
    struct SwiftNetServer* const server,
    void (* const new_handler)(struct SwiftNetServerPacketData* const, void* const),
    void* const user_arg
);

// Set a custom message (packet) handler for the client.
extern void swiftnet_client_set_message_handler(
    struct SwiftNetClientConnection* const client,
    void (* const new_handler)(struct SwiftNetClientPacketData* const, void* const),
    void* const user_arg
);
// Append data to a packet buffer.
extern void swiftnet_append_to_buffer(
    const void* restrict const data,
    const uint32_t data_size,
    struct SwiftNetPacketBuffer* restrict const buffer 
);

// Clean up and free resources for a client connection.
extern void swiftnet_client_cleanup(struct SwiftNetClientConnection* const client);

// Clean up and free resources for a server.
extern void swiftnet_server_cleanup(struct SwiftNetServer* const server);

// Initialize the SwiftNet library.
extern void swiftnet_initialize();

// Send a packet from the client to its connected server.
extern void swiftnet_client_send_packet(
    struct SwiftNetClientConnection* const client,
    struct SwiftNetPacketBuffer* restrict const packet,
    const uint32_t bytes_to_send
);

// Send a packet from the server to a specified client.
extern void swiftnet_server_send_packet(
    struct SwiftNetServer* const server,
    struct SwiftNetPacketBuffer* restrict const packet,
    const struct SwiftNetClientAddrData target,
    const uint32_t bytes_to_send
);


// Create a packet buffer (client).
extern struct SwiftNetPacketBuffer swiftnet_client_create_packet_buffer(const uint32_t buffer_size, const struct SwiftNetClientConnection* const client_connection);

// Create a packet buffer (server).
extern struct SwiftNetPacketBuffer swiftnet_server_create_packet_buffer(const uint32_t buffer_size, const struct SwiftNetServer* const server);

// Resizes packet buffer (client).
extern void swiftnet_client_resize_packet_buffer(uint32_t new_buffer_size, struct SwiftNetPacketBuffer* restrict const, const struct SwiftNetClientConnection* const client_connection);

// Resizes packet buffer (server).
extern void swiftnet_server_resize_packet_buffer(uint32_t new_buffer_size, struct SwiftNetPacketBuffer* restrict const, const struct SwiftNetServer* const server);

// Writes to packet buffer at specific offset (client).
extern void swiftnet_client_write_packet_buffer(const uint32_t byte_offset, struct SwiftNetPacketBuffer* restrict const, void* restrict const data, const uint32_t data_size, const struct SwiftNetClientConnection* const client_connection);

// Writes to packet buffer at specific offset (server).
extern void swiftnet_server_write_packet_buffer(const uint32_t byte_offset, struct SwiftNetPacketBuffer* restrict const, void* restrict const data, const uint32_t data_size, const struct SwiftNetServer* const server);

// Destroy a packet buffer (client).
extern void swiftnet_client_destroy_packet_buffer(const struct SwiftNetPacketBuffer* restrict const packet, const struct SwiftNetClientConnection* const client_connection);

// Destroy a packet buffer (server).
extern void swiftnet_server_destroy_packet_buffer(const struct SwiftNetPacketBuffer* restrict const packet, const struct SwiftNetServer* const server);

// Create and initialize a server.
extern struct SwiftNetServer* swiftnet_create_server(const uint16_t port, const bool loopback);

// Create and initialize a client connection.
extern struct SwiftNetClientConnection* swiftnet_create_client(
    const char* const ip_address,
    const uint16_t port,
    const uint32_t timeout_ms
);

// Read data from a client packet.
extern void* swiftnet_client_read_packet(struct SwiftNetClientPacketData* restrict const packet_data, const uint32_t data_size);

// Read data from a server packet.
extern void* swiftnet_server_read_packet(struct SwiftNetServerPacketData* restrict const packet_data, const uint32_t data_size);

// Destroy client packet data and release memory.
extern void swiftnet_client_destroy_packet_data(
    struct SwiftNetClientPacketData* restrict const packet_data,
    struct SwiftNetClientConnection* const client_conn
);

// Destroy server packet data and release memory.
extern void swiftnet_server_destroy_packet_data(
    struct SwiftNetServerPacketData* restrict const packet_data,
    struct SwiftNetServer* const server
);

// Clean up the entire SwiftNet library.
extern void swiftnet_cleanup();

#ifndef SWIFT_NET_DISABLE_REQUESTS

// Make a request from a client and wait for a response.
extern struct SwiftNetClientPacketData* swiftnet_client_make_request(
    struct SwiftNetClientConnection* const client,
    struct SwiftNetPacketBuffer* const packet,
    const uint32_t timeout_ms,
    const uint32_t bytes_to_send
);

// Make a request from the server to a specific client and wait for response.
extern struct SwiftNetServerPacketData* swiftnet_server_make_request(
    struct SwiftNetServer* const server,
    struct SwiftNetPacketBuffer* const packet,
    const struct SwiftNetClientAddrData addr_data,
    const uint32_t timeout_ms,
    const uint32_t bytes_to_send
);

// Send a response from a client.
extern void swiftnet_client_make_response(
    struct SwiftNetClientConnection* const client,
    struct SwiftNetClientPacketData* const packet_data,
    struct SwiftNetPacketBuffer* const buffer,
    const uint32_t bytes_to_send
);

// Send a response from the server.
extern void swiftnet_server_make_response(
    struct SwiftNetServer* const server,
    struct SwiftNetServerPacketData* const packet_data,
    struct SwiftNetPacketBuffer* const buffer,
    const uint32_t bytes_to_send
);
#endif

#ifndef SWIFT_NET_DISABLE_DEBUGGING
// Adds one or more debug flags to the global debugger state.
extern void swiftnet_add_debug_flags(const SwiftNetDebugFlags flags);
// Removes one or more debug flags from the global debugger state.
extern void swiftnet_remove_debug_flags(const SwiftNetDebugFlags flags);
#endif


#ifdef __cplusplus
}
#endif
