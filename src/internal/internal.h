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

typedef enum {
    PACKET_QUEUE_OWNER_NONE = 0x00,
    PACKET_QUEUE_OWNER_HANDLE_PACKETS = 0x01,
    PACKET_QUEUE_OWNER_PROCESS_PACKETS = 0x02
} PacketQueueOwner;

typedef enum {
    PACKET_CALLBACK_QUEUE_OWNER_NONE = 0x00,
    PACKET_CALLBACK_QUEUE_OWNER_PROCESS_PACKETS = 0x01,
    PACKET_CALLBACK_QUEUE_OWNER_EXECUTE_PACKET_CALLBACK = 0x02
} PacketCallbackQueueOwner;

typedef enum {
    PROTOCOL_NUMBER = 253
} SwiftNetProtocol;

#define SIZEOF_FIELD(type, field) sizeof(((type *)0)->field)

#define PRINT_ERROR(fmt, ...) \
    do { fprintf(stderr, fmt " | function: %s | line: %d\n", ##__VA_ARGS__, __FUNCTION__, __LINE__); } while (0)

#define MIN(one, two) (one > two ? two : one)

static const uint16_t crc16_table[256] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    /* ... truncated for brevity ... */
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

typedef enum {
    STACK_CREATING_LOCKED = 0,
    STACK_CREATING_UNLOCKED = 1
} StackCreatingState;

typedef enum {
    ALLOCATOR_STACK_FREE = 0,
    ALLOCATOR_STACK_OCCUPIED = 1
} AllocatorStackState;

/* --- rest of the file unchanged --- */
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

/* ... and all other function declarations remain unchanged ... */
