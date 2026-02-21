#include <stdint.h>
#include <stdlib.h>
#include "internal.h"
#include <arm_neon.h>
#include <string.h>

// Initialized in swiftnet_initialize function with rand
uint64_t seed;

// This hashing function is not really as random as I would want it to be, but it's performant. 
// Can cause some collisions.
static inline uint64_t hash64(const uint8_t* const data, const uint32_t data_size) {
    // Manual SIMD optimization would be preffered in the future.
    uint64_t res = 0;

    for (uint32_t i = 0; i < data_size; i++) {
        res = (res ^ *(data + i)) * seed;
    }

    return res;
}

static inline uint32_t get_key(void* const key_data, const uint32_t data_size, struct SwiftNetHashMap* const hashmap) {
    // Mapping to max value of items allocated
    // Must rehash when scalling hashmap
    return ((__uint128_t)hash64(key_data, data_size) * hashmap->capacity) >> 64;
}

// Must rehash every key. Takes many cpu cycles.
static inline void hashmap_resize(struct SwiftNetHashMap* const hashmap) {
    // Multiply value should be changed by -D flag in the future.
    // For now just literal
    const uint32_t old_capacity = hashmap->capacity;
    const uint32_t new_capacity = hashmap->capacity * 4;
    struct SwiftNetHashMapItem* const old_data_location = hashmap->items;

    hashmap->capacity = new_capacity;

    // Realloc doesn't make sense here bcs we have to rehash and copy rehashed keys.
    hashmap->items = calloc(sizeof(struct SwiftNetHashMapItem), new_capacity);

    for (uint32_t i = 0; i < old_capacity; i++) {
        struct SwiftNetHashMapItem* const current_hashmap_item = old_data_location + i;
        if (current_hashmap_item->value == NULL) {
            continue;
        }

        for (struct SwiftNetHashMapItem* current_linked_item = current_hashmap_item; current_linked_item != NULL; current_linked_item = current_linked_item->next) {
            void* const key_original_data = current_linked_item->key_original_data;
            const uint32_t key_original_data_size = current_linked_item->key_original_data_size;

            const uint64_t new_key = get_key(key_original_data, key_original_data_size, hashmap);

            struct SwiftNetHashMapItem* new_mem_hashmap_item = hashmap->items + new_key;
            if (new_mem_hashmap_item->value != NULL) {
                // Get last item
                while (new_mem_hashmap_item->next != NULL) {
                    new_mem_hashmap_item = new_mem_hashmap_item->next;
                }

                struct SwiftNetHashMapItem* const hashmap_item_new_allocation = allocator_allocate(&hashmap_item_memory_allocator);
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

struct SwiftNetHashMap hashmap_create() {
    return (struct SwiftNetHashMap){
        .capacity = 0xFF,
        .items = calloc(sizeof(struct SwiftNetHashMapItem), 0xFF)
    };
}

void* hashmap_get(void* const key_data, const uint32_t data_size, struct SwiftNetHashMap* restrict const hashmap) {
    const uint64_t key = get_key(key_data, data_size, hashmap);

    struct SwiftNetHashMapItem* current_item = hashmap->items + key;

    if (current_item->next == NULL) {
        return current_item->value;
    }

    while (current_item != NULL) {
        if (data_size == current_item->key_original_data_size && memcmp(current_item->key_original_data, key_data, data_size) == 0) {
            return current_item->value;
        }

        current_item = current_item->next;

        continue;
    }

    return NULL;
}

void hashmap_insert(void* const key_data, const uint32_t data_size, void* const value, struct SwiftNetHashMap* restrict const hashmap) {
    const uint64_t key = get_key(key_data, data_size, hashmap);

    struct SwiftNetHashMapItem* current_target_item = hashmap->items + key;

    while (current_target_item->value != NULL) {
        if (current_target_item->next == NULL) {
            struct SwiftNetHashMapItem* const new_item = allocator_allocate(&hashmap_item_memory_allocator);

            current_target_item->next = new_item;

            current_target_item = new_item;
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

    if (hashmap->size >= hashmap->capacity) {
        hashmap_resize(hashmap);
    }
}

void hashmap_remove(void* const key_data, const uint32_t data_size, struct SwiftNetHashMap* const hashmap) {
    const uint64_t key = get_key(key_data, data_size, hashmap);

    struct SwiftNetHashMapItem* previous_target_item = hashmap->items + key;
    struct SwiftNetHashMapItem* current_target_item = hashmap->items + key;

    while (current_target_item != NULL) {
        if (data_size == current_target_item->key_original_data_size && memcmp(current_target_item->key_original_data, key_data, data_size) == 0) {
            break;
        }

        previous_target_item = current_target_item;
        current_target_item = current_target_item->next;

        continue;
    }

    if (current_target_item == previous_target_item) {
        current_target_item->value = NULL;

        struct SwiftNetHashMapItem* const next = current_target_item->next;

        if (next != NULL) {
            memcpy(current_target_item, next, sizeof(struct SwiftNetHashMapItem));

            next->value = NULL;

            allocator_free(&hashmap_item_memory_allocator, next);
        }
    } else {
        previous_target_item->next = current_target_item->next;

        current_target_item->value = NULL;
        current_target_item->next = NULL;

        allocator_free(&hashmap_item_memory_allocator, current_target_item);
    }

    hashmap->size--;
}

void hashmap_destroy(struct SwiftNetHashMap* const hashmap) {
    for (uint32_t i = 0; i < hashmap->capacity; i++) {
        struct SwiftNetHashMapItem* const current_item = hashmap->items + i;
        if (current_item->value == NULL) {
            continue;
        }

        // Dealloc all ->next
        for (struct SwiftNetHashMapItem* current_linked_item = current_item->next; current_linked_item != NULL;) {
            struct SwiftNetHashMapItem* const next_item = current_linked_item->next;

            allocator_free(&hashmap_item_memory_allocator, current_linked_item);

            current_linked_item = next_item;

            continue;
        }
    }

    free(hashmap->items);
}
