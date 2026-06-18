#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "internal.h"
#include <arm_neon.h>
#include <string.h>
#include <sys/types.h>

// Initialized in swiftnet_initialize function with rand
uint64_t seed;

// This hashing function is not really as random as I would want it to be, but it's performant. 
// Can cause some collisions.
static inline uint64_t hash64(const uint8_t* const data, const uint32_t data_size) {
    uint64_t res;
    uint32_t i;


    res = 0;

    for(i = 0; i < data_size; i++) {
        res = (res ^ *(data + i)) * seed;
    }

    return res;
}

static inline uint32_t get_key(const void* const key_data, const uint32_t data_size, struct SwiftNetHashMap* const hashmap) {
    // Mapping to max value of items allocated
    // Must rehash when scalling hashmap
    return ((__uint128_t)hash64(key_data, data_size) * hashmap->capacity) >> 64;
}

// Must rehash every key. Takes many cpu cycles.
static inline void hashmap_resize(struct SwiftNetHashMap* const hashmap) {
    uint32_t old_capacity;
    uint32_t new_capacity;
    struct SwiftNetHashMapItem* old_data_location;
    uint32_t i;


    old_capacity = hashmap->capacity;
    new_capacity = hashmap->capacity * 4;
    old_data_location = hashmap->items;

    hashmap->capacity = new_capacity;

    // Realloc doesn't make sense here bcs we have to rehash and copy rehashed keys.
    hashmap->items = calloc(sizeof(struct SwiftNetHashMapItem), new_capacity);

    free(hashmap->item_occupation);

    hashmap->item_occupation = calloc(sizeof(uint32_t), (new_capacity + 31) / 32);

    for(i = 0; i < old_capacity; i++) {
        struct SwiftNetHashMapItem* current_hashmap_item;
        struct SwiftNetHashMapItem* current_linked_item;
        void* key_original_data;
        uint32_t key_original_data_size;
        uint64_t new_key;
        struct SwiftNetHashMapItem* new_mem_hashmap_item;
        uint32_t byte;
        uint8_t bit;
        struct SwiftNetHashMapItem* hashmap_item_new_allocation;


        current_hashmap_item = old_data_location + i;
        if(current_hashmap_item->value == NULL) {
            continue;
        }

        for(current_linked_item = current_hashmap_item; current_linked_item != NULL; current_linked_item = current_linked_item->next) {
            key_original_data = current_linked_item->key_original_data;
            key_original_data_size = current_linked_item->key_original_data_size;

            new_key = get_key(key_original_data, key_original_data_size, hashmap);

            new_mem_hashmap_item = hashmap->items + new_key;

            byte = new_key / 32;
            bit = new_key % 32;

            *(hashmap->item_occupation + byte) |= 1 << bit;

            if(new_mem_hashmap_item->value != NULL) {
                while(new_mem_hashmap_item->next != NULL) {
                    new_mem_hashmap_item = new_mem_hashmap_item->next;
                }

                hashmap_item_new_allocation = allocator_allocate(&hashmap_item_memory_allocator);
                *hashmap_item_new_allocation = (struct SwiftNetHashMapItem){
                    .key_original_data = key_original_data,
                    .key_original_data_size = key_original_data_size,
                    .next = NULL,
                    .value = current_linked_item->value
                };

                new_mem_hashmap_item->next = hashmap_item_new_allocation;
            } else {
                *new_mem_hashmap_item = (struct SwiftNetHashMapItem){
                    .key_original_data = key_original_data,
                    .key_original_data_size = key_original_data_size,
                    .next = NULL,
                    .value = current_linked_item->value
                };
            }
        }
    }

    free(old_data_location);
}

struct SwiftNetHashMap hashmap_create(struct SwiftNetMemoryAllocator* const key_memory_allocator) {
    return (struct SwiftNetHashMap){
        .capacity = 0x40 * SWIFT_NET_MEMORY_USAGE,
        .items = calloc(sizeof(struct SwiftNetHashMapItem), 0x40 * SWIFT_NET_MEMORY_USAGE),
        .size = 0,
        .item_occupation = calloc(sizeof(uint32_t), ((0x40 * SWIFT_NET_MEMORY_USAGE) + 31) / 32),
        .key_memory_allocator = key_memory_allocator
    };
}

void* hashmap_get(const void* const key_data, const uint32_t data_size, struct SwiftNetHashMap* const hashmap) {
    uint64_t key;
    struct SwiftNetHashMapItem* current_item;


    key = get_key(key_data, data_size, hashmap);

    current_item = hashmap->items + key;

    goto loop;

loop:
    if(current_item == NULL) {
        goto exit;
    }

    if(data_size == current_item->key_original_data_size && memcmp(current_item->key_original_data, key_data, data_size) == 0) {
        return current_item->value;
    }

    current_item = current_item->next;

    goto loop;


exit:
    return NULL;
}

void hashmap_insert(void* const key_data, const uint32_t data_size, void* const value, struct SwiftNetHashMap* const hashmap) {
    uint64_t key;
    struct SwiftNetHashMapItem* current_target_item;
    struct SwiftNetHashMapItem* new_item;
    uint32_t byte;
    uint8_t bit;


    key = get_key(key_data, data_size, hashmap);

    current_target_item = hashmap->items + key;

    while(current_target_item->value != NULL) {
        if(current_target_item->next == NULL) {
            new_item = allocator_allocate(&hashmap_item_memory_allocator);

            current_target_item->next = new_item;

            current_target_item = new_item;

            break;
        } else {
            current_target_item = current_target_item->next;
        }
    }

    *current_target_item = (struct SwiftNetHashMapItem){
        .key_original_data = key_data,
        .key_original_data_size = data_size,
        .value = value,
        .next = NULL
    };

    hashmap->size++;

    byte = key / 32;
    bit = key % 32;

    *(hashmap->item_occupation + byte) |= 0 << bit;

    if(hashmap->size >= hashmap->capacity) {
        hashmap_resize(hashmap);
    }
}

void free_hashmap_item_key(struct SwiftNetHashMap* const hashmap, struct SwiftNetHashMapItem* const hashmap_item) {
    if(hashmap->key_memory_allocator == NULL) {
        free(hashmap_item->key_original_data);
    } else {
        allocator_free(hashmap->key_memory_allocator, hashmap_item->key_original_data);
    }
}

void hashmap_remove(void* const key_data, const uint32_t data_size, struct SwiftNetHashMap* const hashmap) {
    uint64_t key;
    struct SwiftNetHashMapItem* previous_target_item;
    struct SwiftNetHashMapItem* current_target_item;
    uint32_t byte;
    uint8_t bit;
    struct SwiftNetHashMapItem* next;


    key = get_key(key_data, data_size, hashmap);

    previous_target_item = hashmap->items + key;
    current_target_item = hashmap->items + key;

    if(current_target_item->next == NULL) {
        byte = key / 32;
        bit = key % 32;

        *(hashmap->item_occupation + byte) &= ~(0 << bit);
    }

    goto find_item;


find_item:
    if(current_target_item == NULL) {
        goto exit;
    }

    if(data_size == current_target_item->key_original_data_size && memcmp(current_target_item->key_original_data, key_data, data_size) == 0) {
        goto remove_item;
    }

    previous_target_item = current_target_item;
    current_target_item = current_target_item->next;

    goto find_item;


remove_item:
    if(current_target_item == previous_target_item) {
        current_target_item->value = NULL;

        next = current_target_item->next;

        if(next != NULL) {
            free_hashmap_item_key(hashmap, current_target_item);

            memcpy(current_target_item, next, sizeof(struct SwiftNetHashMapItem));

            next->value = NULL;
            next->next = NULL;

            allocator_free(&hashmap_item_memory_allocator, next);
        }
    } else {
        previous_target_item->next = current_target_item->next;

        current_target_item->value = NULL;
        current_target_item->next = NULL;

        free_hashmap_item_key(hashmap, current_target_item);

        allocator_free(&hashmap_item_memory_allocator, current_target_item);
    }

    hashmap->size--;


exit:
    return;
}

void hashmap_destroy(struct SwiftNetHashMap* const hashmap) {
    uint32_t i;


    for(i = 0; i < hashmap->capacity; i++) {
        struct SwiftNetHashMapItem* current_item;
        struct SwiftNetHashMapItem* current_linked_item;
        struct SwiftNetHashMapItem* next_item;


        current_item = hashmap->items + i;
        if(current_item->value == NULL) {
            continue;
        }

        for(current_linked_item = current_item->next; current_linked_item != NULL;) {
            next_item = current_linked_item->next;

            free_hashmap_item_key(hashmap, current_linked_item);

            allocator_free(&hashmap_item_memory_allocator, current_linked_item);

            current_linked_item = next_item;
        }
    }

    free(hashmap->items);
}