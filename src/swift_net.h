#pragma once

#include <stdint.h>
#ifdef __cplusplus
    extern "C" {

    #define restrict __restrict__
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <pcap/pcap.h>

#ifndef SWIFT_NET_DISABLE_ERROR_CHECKING
    #define SWIFT_NET_ERROR
#endif

#ifndef SWIFT_NET_DISABLE_REQUESTS
    #define SWIFT_NET_REQUESTS
#endif

#ifndef SWIFT_NET_DISABLE_DEBUGGING
    #define SWIFT_NET_DEBUG
#endif

#define PACKET_TYPE_MESSAGE 0x01
#define PACKET_TYPE_REQUEST_INFORMATION 0x02
#define PACKET_TYPE_SEND_LOST_PACKETS_REQUEST 0x03
#define PACKET_TYPE_SEND_LOST_PACKETS_RESPONSE 0x04
#define PACKET_TYPE_SUCCESSFULLY_RECEIVED_PACKET 0x05
#define PACKET_TYPE_REQUEST 0x06
#ifdef SWIFT_NET_REQUESTS
#define PACKET_TYPE_RESPONSE 0x07
#endif

#define PACKET_INFO_ID_NONE 0xFFFF

#define unlikely(x) __builtin_expect((x), 0x00)
#define likely(x) __builtin_expect((x), 0x01)

extern uint32_t maximum_transmission_unit;

#ifdef SWIFT_NET_DEBUG
enum SwiftNetDebugFlags {
    DEBUG_PACKETS_SENDING = 1u << 0,
    DEBUG_PACKETS_RECEIVING = 1u << 1,
    DEBUG_INITIALIZATION = 1u << 2,
    DEBUG_LOST_PACKETS = 1u << 3
};

struct SwiftNetDebugger {
    uint32_t flags;
};
#endif

struct SwiftNetPortInfo {
    uint16_t destination_port;
    uint16_t source_port;
};

struct SwiftNetClientAddrData {
    struct in_addr sender_address;
    uint32_t maximum_transmission_unit;
    uint16_t port;
    uint8_t mac_address[6];
};

struct SwiftNetPacketClientMetadata {
    uint32_t data_length;
    struct SwiftNetPortInfo port_info;
    uint16_t packet_id;
    #ifdef SWIFT_NET_REQUESTS
        bool expecting_response;
    #endif
};

struct SwiftNetPacketInfo {
    uint32_t packet_length;
    struct SwiftNetPortInfo port_info;
    uint8_t packet_type;
    uint32_t chunk_amount;
    uint32_t chunk_index;
    uint32_t maximum_transmission_unit;
};

struct SwiftNetPendingMessage {
    uint8_t* packet_data_start;
    struct SwiftNetPacketInfo packet_info;
    uint16_t packet_id;
    struct in_addr sender_address;
    uint8_t* chunks_received;
    uint32_t chunks_received_length;
    uint32_t chunks_received_number;
};

struct SwiftNetPacketServerMetadata {
    uint32_t data_length;
    struct SwiftNetPortInfo port_info;
    struct SwiftNetClientAddrData sender;
    uint16_t packet_id;
    #ifdef SWIFT_NET_REQUESTS
        bool expecting_response;
    #endif
};

struct SwiftNetServerInformation {
    uint32_t maximum_transmission_unit;
};

enum PacketSendingUpdated {
    NO_UPDATE,
    UPDATED_LOST_CHUNKS,
    SUCCESSFULLY_RECEIVED
};

struct SwiftNetPacketSending {
    uint16_t packet_id;
    uint32_t* lost_chunks;
    uint32_t lost_chunks_size;
    _Atomic enum PacketSendingUpdated updated;
    _Atomic bool locked;
};

struct SwiftNetPacketCompleted {
    uint16_t packet_id;
};

struct SwiftNetPacketBuffer {
    uint8_t* packet_buffer_start;   // Start of the allocated buffer
    uint8_t* packet_data_start;     // Start of the stored data
    uint8_t* packet_append_pointer; // Current position to append new data
};

struct PacketQueueNode {
    struct PacketQueueNode* next;
    uint8_t* data;
    uint32_t data_read;
    struct in_addr sender_address;
};

struct PacketQueue {
    _Atomic uint32_t owner;
    struct PacketQueueNode* first_node;
    struct PacketQueueNode* last_node;
};

struct PacketCallbackQueueNode {
    void* packet_data;
    struct SwiftNetPendingMessage* pending_message;
    uint16_t packet_id;
    struct PacketCallbackQueueNode* next;
};

struct SwiftNetServerPacketData {
    uint8_t* data;
    uint8_t* current_pointer;
    struct SwiftNetPacketServerMetadata metadata;
    struct SwiftNetPendingMessage* internal_pending_message; // Do not use!!
};

struct SwiftNetClientPacketData {
    uint8_t* data;
    uint8_t* current_pointer;
    struct SwiftNetPacketClientMetadata metadata;
    struct SwiftNetPendingMessage* internal_pending_message; // Do not use!!
};

struct PacketCallbackQueue {
    _Atomic uint32_t owner;
    struct PacketCallbackQueueNode* first_node;
    struct PacketCallbackQueueNode* last_node;
};

struct SwiftNetSentSuccessfullyCompletedPacketSignal {
    uint16_t packet_id;
    bool confirmed;
};

struct SwiftNetMemoryAllocatorStack {
    _Atomic uint32_t size;
    void* pointers;
    void* data;
    _Atomic(void*) next;
    _Atomic(void*) previous;
    _Atomic uint8_t owner;
    #ifdef SWIFT_NET_INTERNAL_TESTING 
    uint8_t* ptr_status;
    _Atomic bool accessing_ptr_status;
    #endif
};

struct SwiftNetChunkStorageManager {
    _Atomic(void*) first_item;
    _Atomic(void*) last_item;
};

struct SwiftNetMemoryAllocator {
    struct SwiftNetChunkStorageManager data;
    uint32_t item_size;
    uint32_t chunk_item_amount;
    _Atomic uint8_t creating_stack;
};

struct SwiftNetVector {
    void* data;
    uint32_t size;
    uint32_t capacity;
    _Atomic uint8_t locked;
};

// Connection data
struct SwiftNetClientConnection {
    pcap_t* pcap;
    struct ether_header eth_header;
    struct SwiftNetPortInfo port_info;
    struct in_addr server_addr;
    _Atomic(void (*)(struct SwiftNetClientPacketData* const, void* const user)) packet_handler;
    _Atomic(void*) packet_handler_user_arg;
    _Atomic bool closing;
    _Atomic bool initialized;
    uint16_t addr_type;
    bool loopback;
    pthread_t process_packets_thread;
    pthread_t execute_callback_thread;
    uint32_t maximum_transmission_unit;
    struct SwiftNetVector pending_messages;
    struct SwiftNetMemoryAllocator pending_messages_memory_allocator;
    struct SwiftNetVector packets_sending;
    struct SwiftNetMemoryAllocator packets_sending_memory_allocator;
    struct SwiftNetVector packets_completed;
    struct SwiftNetMemoryAllocator packets_completed_memory_allocator;
    struct PacketQueue packet_queue;
    struct PacketCallbackQueue packet_callback_queue;
    uint8_t prepend_size;
};

struct SwiftNetServer {
    pcap_t* pcap;
    struct ether_header eth_header;
    uint16_t server_port;
    _Atomic(void (*)(struct SwiftNetServerPacketData* const, void* const user)) packet_handler;
    _Atomic(void*) packet_handler_user_arg;
    _Atomic bool closing;
    uint16_t addr_type;
    bool loopback;
    pthread_t process_packets_thread;
    pthread_t execute_callback_thread;
    struct SwiftNetVector pending_messages;
    struct SwiftNetMemoryAllocator pending_messages_memory_allocator;
    struct SwiftNetVector packets_sending;
    struct SwiftNetMemoryAllocator packets_sending_memory_allocator;
    struct SwiftNetVector packets_completed;
    struct SwiftNetMemoryAllocator packets_completed_memory_allocator;
    uint8_t* current_read_pointer;
    struct PacketQueue packet_queue;
    struct PacketCallbackQueue packet_callback_queue;
    uint8_t prepend_size;
};

/**
 * @brief Set a custom message handler for the server.
 * @param server Pointer to the server.
 * @param new_handler Function pointer to the new message handler.
 */
extern void swiftnet_server_set_message_handler(
    struct SwiftNetServer* const server,
    void (* const new_handler)(struct SwiftNetServerPacketData* const, void* const),
    void* const user_arg
);

/**
 * @brief Set a custom message handler for the client connection.
 * @param client Pointer to the client connection.
 * @param new_handler Function pointer to the new message handler.
 */
extern void swiftnet_client_set_message_handler(
    struct SwiftNetClientConnection* const client,
    void (* const new_handler)(struct SwiftNetClientPacketData* const, void* const),
    void* const user_arg
);

/**
 * @brief Append data to a client packet buffer.
 * @param data Pointer to the data to append.
 * @param data_size Size of the data in bytes.
 * @param packet Pointer to the client packet buffer.
 */
extern void swiftnet_client_append_to_packet(
    const void* const data,
    const uint32_t data_size,
    struct SwiftNetPacketBuffer* const packet
);

/**
 * @brief Append data to a server packet buffer.
 * @param data Pointer to the data to append.
 * @param data_size Size of the data in bytes.
 * @param packet Pointer to the server packet buffer.
 */
extern void swiftnet_server_append_to_packet(
    const void* const data,
    const uint32_t data_size,
    struct SwiftNetPacketBuffer* const packet
);

/**
 * @brief Clean up and free resources for a client connection.
 * @param client Pointer to the client connection.
 */
extern void swiftnet_client_cleanup(struct SwiftNetClientConnection* const client);

/**
 * @brief Clean up and free resources for a server.
 * @param server Pointer to the server.
 */
extern void swiftnet_server_cleanup(struct SwiftNetServer* const server);

/**
 * @brief Initialize the SwiftNet library. Must be called before using any other functions.
 */
extern void swiftnet_initialize();

/**
 * @brief Send a packet from the client to its connected server.
 * @param client Pointer to the client connection.
 * @param packet Pointer to the packet buffer to send.
 */
extern void swiftnet_client_send_packet(
    struct SwiftNetClientConnection* const client,
    struct SwiftNetPacketBuffer* const packet
);

/**
 * @brief Send a packet from the server to a specific client.
 * @param server Pointer to the server.
 * @param packet Pointer to the packet buffer to send.
 * @param target Target client address data.
 */
extern void swiftnet_server_send_packet(
    struct SwiftNetServer* const server,
    struct SwiftNetPacketBuffer* const packet,
    const struct SwiftNetClientAddrData target
);

/**
 * @brief Create a packet buffer for the server.
 * @param buffer_size Size of the buffer in bytes.
 * @return SwiftNetPacketBuffer Initialized packet buffer.
 */
extern struct SwiftNetPacketBuffer swiftnet_server_create_packet_buffer(const uint32_t buffer_size);

/**
 * @brief Create a packet buffer for the client.
 * @param buffer_size Size of the buffer in bytes.
 * @return SwiftNetPacketBuffer Initialized packet buffer.
 */
extern struct SwiftNetPacketBuffer swiftnet_client_create_packet_buffer(const uint32_t buffer_size);

/**
 * @brief Destroy a server packet buffer and free resources.
 * @param packet Pointer to the server packet buffer.
 */
extern void swiftnet_server_destroy_packet_buffer(const struct SwiftNetPacketBuffer* const packet);

/**
 * @brief Destroy a client packet buffer and free resources.
 * @param packet Pointer to the client packet buffer.
 */
extern void swiftnet_client_destroy_packet_buffer(const struct SwiftNetPacketBuffer* const packet);

/**
 * @brief Create and initialize a server.
 * @param port Port number to bind the server to.
 * @param loopback If true, server binds only to loopback interface.
 * @return Pointer to initialized SwiftNetServer, or NULL if unexpected error happened.
 */
extern struct SwiftNetServer* swiftnet_create_server(const uint16_t port, const bool loopback);

/**
 * @brief Create and initialize a client connection.
 * @param ip_address IP address of the server to connect to.
 * @param port Server port to connect to.
 * @param timeout_ms Connection timeout in milliseconds.
 * @return Pointer to initialized SwiftNetClientConnection, or NULL if server failed to respond.
 */
extern struct SwiftNetClientConnection* swiftnet_create_client(
    const char* const ip_address,
    const uint16_t port,
    const uint32_t timeout_ms
);

/**
 * @brief Read data from a client packet.
 * @param packet_data Pointer to client packet data.
 * @param data_size Number of bytes to read.
 * @return Pointer to the read data, or NULL if read more data than there is.
 */
extern void* swiftnet_client_read_packet(struct SwiftNetClientPacketData* const packet_data, const uint32_t data_size);

/**
 * @brief Read data from a server packet.
 * @param packet_data Pointer to server packet data.
 * @param data_size Number of bytes to read.
 * @return Pointer to the read data, or NULL if read more data than there is.
 */
extern void* swiftnet_server_read_packet(struct SwiftNetServerPacketData* const packet_data, const uint32_t data_size);

/**
 * @brief Destroy client packet data and release memory.
 * @param packet_data Pointer to client packet data.
 * @param client_conn Pointer to the client connection.
 */
extern void swiftnet_client_destroy_packet_data(
    struct SwiftNetClientPacketData* const packet_data,
    struct SwiftNetClientConnection* const client_conn
);

/**
 * @brief Destroy server packet data and release memory.
 * @param packet_data Pointer to server packet data.
 * @param server Pointer to the server.
 */
extern void swiftnet_server_destroy_packet_data(
    struct SwiftNetServerPacketData* const packet_data,
    struct SwiftNetServer* const server
);

/**
 * @brief Clean up the entire SwiftNet library.
 */
extern void swiftnet_cleanup();

#ifdef SWIFT_NET_REQUESTS
/**
 * @brief Make a request from a client and wait for a response.
 * @param client Pointer to the client connection.
 * @param packet Pointer to the packet buffer containing the request.
 * @param timeout_ms Timeout in milliseconds.
 * @return Pointer to client packet data containing the response, or NULL if server failed to respond.
 */
extern struct SwiftNetClientPacketData* swiftnet_client_make_request(
    struct SwiftNetClientConnection* const client,
    struct SwiftNetPacketBuffer* const packet,
    const uint32_t timeout_ms
);

/**
 * @brief Make a request from the server to a specific client and wait for response.
 * @param server Pointer to the server.
 * @param packet Pointer to the packet buffer containing the request.
 * @param addr_data Target client address.
 * @param timeout_ms Timeout in milliseconds.
 * @return Pointer to server packet data containing the response, or NULL if client failed to respond.
 */
extern struct SwiftNetServerPacketData* swiftnet_server_make_request(
    struct SwiftNetServer* const server,
    struct SwiftNetPacketBuffer* const packet,
    const struct SwiftNetClientAddrData addr_data,
    const uint32_t timeout_ms
);

/**
 * @brief Send a response from a client.
 * @param client Pointer to the client connection.
 * @param packet_data Pointer to the request packet data.
 * @param buffer Packet buffer containing the response.
 */
extern void swiftnet_client_make_response(
    struct SwiftNetClientConnection* const client,
    struct SwiftNetClientPacketData* const packet_data,
    struct SwiftNetPacketBuffer* const buffer
);

/**
 * @brief Send a response from the server.
 * @param server Pointer to the server.
 * @param packet_data Pointer to the request packet data.
 * @param buffer Packet buffer containing the response.
*/
extern void swiftnet_server_make_response(
    struct SwiftNetServer* const server,
    struct SwiftNetServerPacketData* const packet_data,
    struct SwiftNetPacketBuffer* const buffer
);
#endif

#ifdef SWIFT_NET_DEBUG
    /**
    * @brief Adds one or more debug flags to the global debugger state.
    *
    * This function performs a bitwise OR on the existing debugger flags,
    * enabling any debug options specified in @p flags while leaving the
    * previously enabled flags untouched.
    *
    * @param flags Bitmask of debug flags to enable. Multiple flags may be
    * combined using bitwise OR.
    */
    extern void swiftnet_add_debug_flags(const uint32_t flags);
#endif

#ifdef __cplusplus
    }
#endif
