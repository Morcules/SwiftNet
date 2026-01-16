#pragma once

#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdlib.h>
#include "../swift_net.h"
#include <sys/socket.h>
#include <stdarg.h>
#include <stdio.h>
#include <net/if.h>

#ifdef __linux__
    #define LOOPBACK_INTERFACE_NAME "lo\0"
#elif defined(__APPLE__)
    #define LOOPBACK_INTERFACE_NAME "lo0\0"
#endif

typedef enum {
    REQUEST_LOST_PACKETS_RETURN_UPDATED_BIT_ARRAY = 0x00,
    REQUEST_LOST_PACKETS_RETURN_COMPLETED_PACKET  = 0x01
} RequestLostPacketsReturnType;

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

#define HANDLE_CHECKSUM(buffer, size, prepend_size) \
    uint16_t checksum = htons(crc16(buffer, size)); \
    memcpy(buffer + prepend_size + offsetof(struct ip, ip_sum), &checksum, sizeof(checksum));

#define PROT_NUMBER 253

#define SIZEOF_FIELD(type, field) sizeof(((type *)0)->field)

#define PRINT_ERROR(fmt, ...) \
    do { fprintf(stderr, fmt " | function: %s | line: %d\n", ##__VA_ARGS__, __FUNCTION__, __LINE__); } while (0)

#define MIN(one, two) (one > two ? two : one)

static const uint16_t crc16_table[256] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

static inline uint16_t crc16(const uint8_t *data, size_t length) {
    uint16_t crc = 0xFFFF;
    
    for (size_t i = 0; i < length; i++) {
        uint8_t byte = data[i];
        crc = (crc >> 8) ^ crc16_table[(crc ^ byte) & 0xFF];
    }

    return crc ^ 0xFFFF;
}

enum StackCreatingState {
    STACK_CREATING_LOCKED = 0,
    STACK_CREATING_UNLOCKED = 1
};

enum AllocatorStackState {
    ALLOCATOR_STACK_FREE = 0,
    ALLOCATOR_STACK_OCCUPIED = 1
};

struct Listener {
    pcap_t* pcap;
    char interface_name[IFNAMSIZ];
    struct SwiftNetVector servers;
    struct SwiftNetVector client_connections;
    pthread_t listener_thread;
    bool loopback;
    uint16_t addr_type;
};

enum ConnectionType {
    CONNECTION_TYPE_SERVER,
    CONNECTION_TYPE_CLIENT
};

extern struct SwiftNetVector listeners;

extern int get_default_interface_and_mac(char *restrict interface_name, uint32_t interface_name_length, uint8_t mac_out[6], int sockfd);
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
extern pcap_t* swiftnet_pcap_open(const char* interface);
extern int swiftnet_pcap_send(pcap_t *pcap, const uint8_t *data, int len);

extern void* check_existing_listener(const char* interface_name, void* const connection, const enum ConnectionType connection_type, const bool loopback);

#ifdef SWIFT_NET_INTERNAL_TESTING
    extern uint32_t bytes_leaked;
    extern uint32_t items_leaked;
#endif

#ifdef SWIFT_NET_DEBUG
    extern struct SwiftNetDebugger debugger;

    static inline bool check_debug_flag(const enum SwiftNetDebugFlags flag) {
        return (debugger.flags & flag) != 0;
    }

    static inline void send_debug_message(const char* message, ...) {
        va_list args;
        va_start(args, message);

        char* prefix = "[DEBUG] ";

        const uint32_t prefix_length = strlen(prefix);
        const uint32_t message_length = strlen(message);

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

extern struct SwiftNetMemoryAllocator allocator_create(const uint32_t item_size, const uint32_t chunk_item_amount);
extern void* allocator_allocate(struct SwiftNetMemoryAllocator* const memory_allocator);
extern void allocator_free(struct SwiftNetMemoryAllocator* const memory_allocator, void* const memory_location);
extern void allocator_destroy(struct SwiftNetMemoryAllocator* const memory_allocator);

extern struct SwiftNetMemoryAllocator packet_queue_node_memory_allocator;
extern struct SwiftNetMemoryAllocator packet_callback_queue_node_memory_allocator;
extern struct SwiftNetMemoryAllocator server_packet_data_memory_allocator;
extern struct SwiftNetMemoryAllocator client_packet_data_memory_allocator;
extern struct SwiftNetMemoryAllocator packet_buffer_memory_allocator;
extern struct SwiftNetMemoryAllocator server_memory_allocator;
extern struct SwiftNetMemoryAllocator client_connection_memory_allocator;
extern struct SwiftNetMemoryAllocator listener_memory_allocator;

extern void* interface_start_listening(void* listener_void);

extern void* vector_get(struct SwiftNetVector* const vector, const uint32_t index);
extern void vector_remove(struct SwiftNetVector* const vector, const uint32_t index);
extern void vector_push(struct SwiftNetVector* const vector, void* const data);
extern void vector_destroy(struct SwiftNetVector* const vector);
extern struct SwiftNetVector vector_create(const uint32_t starting_amount);
extern void vector_lock(struct SwiftNetVector* const vector);
extern void vector_unlock(struct SwiftNetVector* const vector);

extern void* server_start_pcap(void* server_void);
extern void* client_start_pcap(void* client_void);

#ifdef SWIFT_NET_REQUESTS
    struct RequestSent {
        uint16_t packet_id;
        struct in_addr address;
        _Atomic(void*) packet_data;
    };

    extern struct SwiftNetMemoryAllocator requests_sent_memory_allocator;
    extern struct SwiftNetVector requests_sent;
#endif

extern void swiftnet_send_packet(
    const void* const connection,
    const uint32_t target_maximum_transmission_unit,
    const struct SwiftNetPortInfo port_info,
    const struct SwiftNetPacketBuffer* const packet,
    const uint32_t packet_length,
    const struct in_addr* const target_addr,
    struct SwiftNetVector* const packets_sending,
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
        .port_info = port_info
    };
}

static struct ip construct_ip_header(struct in_addr destination_addr, const uint32_t packet_size, const uint16_t packet_id) {
    struct ip ip_header = {
        .ip_v = 4, // Version (ipv4)
        .ip_hl = 5, // Header length
        .ip_tos = 0, // Type of service
        .ip_p = PROT_NUMBER, // Protocol
        .ip_len = htons(packet_size), // Chunk size
        .ip_id = htons(packet_id), // Packet id
        .ip_off = htons(0), // Not used
        .ip_ttl = 64,// Time to live
        .ip_sum = htons(0), // Checksum
        .ip_src = private_ip_address, // Source ip
        .ip_dst = destination_addr // Destination ip
    };

    return ip_header;
}
