#ifdef SWIFT_NET_BACKEND_DPDK
#include "../internal.h"
#include "../networking.h"
#include "../../swift_net.h"
#include <net/ethernet.h>
#include <rte_mbuf.h>
#include <stdint.h>
#include <stdlib.h>
#include <rte_mempool.h>
#include <string.h>

static inline ALWAYS_INLINE uint16_t mbuf_size_for_data(const uint16_t data_size, const uint8_t prepend_size) {
    return data_size + PACKET_HEADER_SIZE + prepend_size + sizeof(struct SwiftNetPacketMetadata);
}

static inline ALWAYS_INLINE uint16_t mbuf_size_for_full_chunk(const uint8_t prepend_size) {
    return maximum_transmission_unit + prepend_size;
}

static inline struct SwiftNetPacketBuffer create_packet_buffer(const uint32_t buffer_size, const struct SwiftNetNetworkData* const network_data) {
    uint32_t chunk_amount;
    uint16_t remaining_data;
    uint16_t data_len_per_packet;
    struct rte_mbuf** buffers;

    data_len_per_packet = (uint16_t)(maximum_transmission_unit - PACKET_HEADER_SIZE);

    remaining_data = (uint16_t)(buffer_size % data_len_per_packet);
    chunk_amount = calculate_chunk_amount(buffer_size, maximum_transmission_unit);

    buffers = malloc(sizeof(void*) * (chunk_amount + 1));

    if (chunk_amount > 0) {
        rte_pktmbuf_alloc_bulk(network_data->mem_pool, buffers, chunk_amount);

        for(uint32_t i = 0; i < chunk_amount; i++) {
            struct rte_mbuf* restrict current_buffer;
            

            current_buffer = buffers[i];

            rte_pktmbuf_append(current_buffer, mbuf_size_for_full_chunk(GET_PREPEND_SIZE(network_data)));
        }
    }
    
    buffers[chunk_amount] = rte_pktmbuf_alloc(network_data->mem_pool);

    rte_pktmbuf_append(buffers[chunk_amount], mbuf_size_for_data(remaining_data, GET_PREPEND_SIZE(network_data)));

    return (struct SwiftNetPacketBuffer){
        .buf_amount = chunk_amount + 1,
        .dpdk_buffers = buffers,
        .total_data_size = buffer_size,
        .data_len_per_packet = data_len_per_packet,
        .append_offset = 0
    };
}

struct SwiftNetPacketBuffer swiftnet_client_create_packet_buffer(const uint32_t buffer_size, const struct SwiftNetClientConnection* const client_connection) {
    return create_packet_buffer(buffer_size, &client_connection->network_data);
}

struct SwiftNetPacketBuffer swiftnet_server_create_packet_buffer(const uint32_t buffer_size, const struct SwiftNetServer* const server) {
    return create_packet_buffer(buffer_size, &server->network_data);
}

static inline void resize_packet_buffer(uint32_t new_buffer_size, struct SwiftNetPacketBuffer* restrict const packet_buffer, const struct SwiftNetNetworkData* const network_data) {
    uint32_t data_size_change;
    uint16_t data_len_per_packet;
    uint8_t prepend_size;
    struct rte_mbuf* restrict last_packet;
    uint16_t last_packet_data_size;

    data_len_per_packet = packet_buffer->data_len_per_packet;
    prepend_size = GET_PREPEND_SIZE(network_data);

    if (unlikely(new_buffer_size == packet_buffer->total_data_size)) {
        return;
    }

    last_packet = packet_buffer->dpdk_buffers[packet_buffer->buf_amount - 1];
    last_packet_data_size = last_packet->data_len - PACKET_HEADER_SIZE - prepend_size;

    if (new_buffer_size > packet_buffer->total_data_size) {
        uint32_t chunk_amount;
        uint16_t remainder;
        uint32_t new_slots;
        struct rte_mbuf** restrict new_buffers;

        data_size_change = new_buffer_size - packet_buffer->total_data_size;

        if (data_size_change + last_packet_data_size <= data_len_per_packet) {
            rte_pktmbuf_append(last_packet, (uint16_t)data_size_change);
            packet_buffer->total_data_size = new_buffer_size;
            return;
        }

        rte_pktmbuf_append(last_packet, data_len_per_packet - last_packet_data_size);
        data_size_change -= data_len_per_packet - last_packet_data_size;

        chunk_amount = calculate_chunk_amount(new_buffer_size, maximum_transmission_unit);
        remainder = (uint16_t)(data_size_change % data_len_per_packet);
        new_slots = chunk_amount + (remainder != 0 ? 1 : 0);

        new_buffers = realloc(packet_buffer->dpdk_buffers, sizeof(void*) * (packet_buffer->buf_amount + new_slots));
        if (unlikely(new_buffers == NULL)) {
            PRINT_ERROR("Failed to realloc");
            exit(EXIT_FAILURE);
        }

        packet_buffer->dpdk_buffers = new_buffers;

        if (chunk_amount > 0) {
            rte_pktmbuf_alloc_bulk(network_data->mem_pool, packet_buffer->dpdk_buffers + packet_buffer->buf_amount, chunk_amount);

            for (uint32_t i = 0; i < chunk_amount; i++) {
                rte_pktmbuf_append(packet_buffer->dpdk_buffers[packet_buffer->buf_amount + i], mbuf_size_for_full_chunk(prepend_size));
            }

            packet_buffer->buf_amount += chunk_amount;
        }

        if (likely(remainder != 0)) {
            struct rte_mbuf* restrict new_last_packet;

            new_last_packet = rte_pktmbuf_alloc(network_data->mem_pool);
            packet_buffer->dpdk_buffers[packet_buffer->buf_amount] = new_last_packet;
            rte_pktmbuf_append(new_last_packet, mbuf_size_for_data(remainder, prepend_size));
            packet_buffer->buf_amount++;
        }

        packet_buffer->total_data_size = new_buffer_size;

        return;
    }

    data_size_change = packet_buffer->total_data_size - new_buffer_size;

    if (data_size_change <= last_packet_data_size) {
        uint16_t new_last_packet_data_size;
        uint16_t new_size;

        new_last_packet_data_size = (uint16_t)(last_packet_data_size - data_size_change);
        new_size = mbuf_size_for_data(new_last_packet_data_size, prepend_size);

        last_packet->data_len = new_size;
        last_packet->pkt_len = new_size;

        packet_buffer->total_data_size = new_buffer_size;

        return;
    }

    data_size_change -= last_packet_data_size;
    rte_pktmbuf_free(last_packet);
    packet_buffer->buf_amount--;

    while (data_size_change >= data_len_per_packet && packet_buffer->buf_amount > 1) {
        rte_pktmbuf_free(packet_buffer->dpdk_buffers[packet_buffer->buf_amount - 1]);
        packet_buffer->buf_amount--;
        data_size_change -= data_len_per_packet;
    }

    last_packet = packet_buffer->dpdk_buffers[packet_buffer->buf_amount - 1];
    last_packet_data_size = last_packet->data_len - PACKET_HEADER_SIZE - prepend_size;

    if (data_size_change >= last_packet_data_size) {
        rte_pktmbuf_free(last_packet);
        packet_buffer->buf_amount--;

        last_packet = rte_pktmbuf_alloc(network_data->mem_pool);
        packet_buffer->dpdk_buffers[packet_buffer->buf_amount] = last_packet;
        rte_pktmbuf_append(last_packet, mbuf_size_for_data(0, prepend_size));
        packet_buffer->buf_amount++;
    } else {
        uint16_t data_size = mbuf_size_for_data((uint16_t)(last_packet_data_size - data_size_change), prepend_size);

        last_packet->data_len = data_size;
        last_packet->pkt_len = data_size;
    }

    packet_buffer->dpdk_buffers = realloc(packet_buffer->dpdk_buffers, sizeof(void*) * packet_buffer->buf_amount);
    packet_buffer->total_data_size = new_buffer_size;
}

void swiftnet_client_resize_packet_buffer(uint32_t new_buffer_size, struct SwiftNetPacketBuffer* restrict const packet_buffer, const struct SwiftNetClientConnection* const client_connection) {
    resize_packet_buffer(new_buffer_size, packet_buffer, &client_connection->network_data);
}

void swiftnet_server_resize_packet_buffer(uint32_t new_buffer_size, struct SwiftNetPacketBuffer* restrict const packet_buffer, const struct SwiftNetServer* const server) {
    resize_packet_buffer(new_buffer_size, packet_buffer, &server->network_data);
}

static inline void write_packet_buffer(const uint32_t byte_offset, struct SwiftNetPacketBuffer* restrict const packet_buffer, const void* restrict data, uint32_t data_size) {
    uint32_t chunk_num_start;
    uint32_t current_offset;
    uint32_t bytes_remaining;

    chunk_num_start = byte_offset < packet_buffer->data_len_per_packet - sizeof(struct SwiftNetPacketMetadata) ? 0 : ((byte_offset - packet_buffer->data_len_per_packet - sizeof(struct SwiftNetPacketMetadata) / packet_buffer->data_len_per_packet)) + 1;
    current_offset = byte_offset == 0 ? 0 : chunk_num_start == 0 ? byte_offset : (byte_offset - sizeof(struct SwiftNetPacketMetadata)) % packet_buffer->data_len_per_packet;
    bytes_remaining = data_size;

    while (bytes_remaining > 0) {
        struct rte_mbuf* restrict current_buf;
        uint8_t* buf_addr;
        uint32_t bytes_this_chunk;
        uint32_t real_offset;
        uint32_t reserved_header;

        current_buf = packet_buffer->dpdk_buffers[chunk_num_start];

        reserved_header = maximum_transmission_unit - packet_buffer->data_len_per_packet + sizeof(struct ether_header) + (chunk_num_start == 0 ? sizeof(struct SwiftNetPacketMetadata) : 0);
        real_offset = reserved_header + current_offset;

        bytes_this_chunk = MIN(maximum_transmission_unit + sizeof(struct ether_header) - real_offset, bytes_remaining);

        buf_addr = rte_pktmbuf_mtod(current_buf, uint8_t*);

        memcpy(buf_addr + real_offset, data, bytes_this_chunk);

        data = (uint8_t*)data + bytes_this_chunk;
        bytes_remaining -= bytes_this_chunk;
        current_offset = 0;
        chunk_num_start++;
    }
}

void swiftnet_client_write_packet_buffer(const uint32_t byte_offset, struct SwiftNetPacketBuffer* restrict const packet_buffer, void* restrict const data, const uint32_t data_size, MAYBE_UNUSED const struct SwiftNetClientConnection* const client_connection) {
    write_packet_buffer(byte_offset, packet_buffer, data, data_size);
}

void swiftnet_server_write_packet_buffer(const uint32_t byte_offset, struct SwiftNetPacketBuffer* restrict const packet_buffer, void* restrict const data, const uint32_t data_size, MAYBE_UNUSED const struct SwiftNetServer* const server) {
    write_packet_buffer(byte_offset, packet_buffer, data, data_size);
}

static inline void validate_append_to_packet_args(const void* restrict const data, const uint32_t data_size) {
    if(unlikely(data == NULL || data_size == 0)) {
        PRINT_ERROR("Error: Invalid arguments given");
        exit(EXIT_FAILURE);
    }
}

void swiftnet_append_to_buffer(const void* restrict const data, const uint32_t data_size, struct SwiftNetPacketBuffer* restrict const buffer) {
    #ifndef SWIFT_NET_DISABLE_ERROR_CHECKING
        validate_append_to_packet_args(data, data_size);
    #endif

    write_packet_buffer(buffer->append_offset, buffer, data, data_size);

    buffer->append_offset += data_size;
}

static inline void destroy_packet_buffer(const struct SwiftNetPacketBuffer* restrict const packet) {
    rte_pktmbuf_free_bulk(packet->dpdk_buffers, packet->buf_amount);
    free(packet->dpdk_buffers);
}

void swiftnet_client_destroy_packet_buffer(const struct SwiftNetPacketBuffer* restrict const packet, MAYBE_UNUSED const struct SwiftNetClientConnection* const client_connection) {
    destroy_packet_buffer(packet);
}

void swiftnet_server_destroy_packet_buffer(const struct SwiftNetPacketBuffer* restrict const packet, MAYBE_UNUSED const struct SwiftNetServer* const server) {
    destroy_packet_buffer(packet);
}
#endif
