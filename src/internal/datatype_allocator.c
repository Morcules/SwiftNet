#include "internal.h"
#include <stdatomic.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static inline void free_stack_lock(struct SwiftNetMemoryAllocatorStack* const stack, struct SwiftNetMemoryAllocator* const allocator) {
    atomic_fetch_and_explicit(&allocator->occupied, ~(1u << stack->index), memory_order_acq_rel);
}

#ifdef SWIFT_NET_INTERNAL_TESTING
static inline void unlock_ptr_status(struct SwiftNetMemoryAllocatorStack* const stack) {
    atomic_store_explicit(&stack->accessing_ptr_status, false, memory_order_release);
}

static inline void lock_ptr_status(struct SwiftNetMemoryAllocatorStack* const stack) {
    bool target = false;

    while(!atomic_compare_exchange_strong_explicit(
        &stack->accessing_ptr_status,
        &target,
        true,
        memory_order_acquire,
        memory_order_relaxed
    )) {
        target = false;
    }
}

static inline void set_memory_status(struct SwiftNetMemoryAllocator* const memory_allocator, void* const memory_location, const uint8_t status) {
    for (uint32_t i = 0; i < memory_allocator->stacks_allocated; i++) {
        struct SwiftNetMemoryAllocatorStack* const stack = memory_allocator->stacks[i];

        if (
            memory_location >= stack->data
            &&
            memory_location <= stack->data + (memory_allocator->item_size * memory_allocator->chunk_item_amount)
        ) {
            const uint32_t offset = memory_location - stack->data;
            const uint32_t index = offset / memory_allocator->item_size;

            const uint32_t byte = index / 8;
            const uint8_t bit = index % 8;

            lock_ptr_status(stack);

            if (status) {
                *(stack->ptr_status + byte) |=  (1u << bit);
            } else {
                *(stack->ptr_status + byte) &= ~(1u << bit);
            }

            unlock_ptr_status(stack);
        }
    }
}

static inline bool is_already_free(struct SwiftNetMemoryAllocator* const memory_allocator, void* const memory_location) {
    for (uint32_t i = 0; i < memory_allocator->stacks_allocated; i++) {
        struct SwiftNetMemoryAllocatorStack* const stack = memory_allocator->stacks[i];
        if (
            memory_location >= stack->data
            &&
            memory_location <= stack->data + (memory_allocator->item_size * memory_allocator->chunk_item_amount)
        ) {
            const uint32_t offset = memory_location - stack->data;
            const uint32_t index = offset / memory_allocator->item_size;

            const uint32_t byte = index / 8;
            const uint8_t bit = index % 8;

            lock_ptr_status(stack);

            if(((*(stack->ptr_status + byte)) & (1u << bit)) != 0) {
                unlock_ptr_status(stack);

                return false;
            } else {
                unlock_ptr_status(stack);

                return true;
            }
        }
    }

    return false;
}
#endif

struct SwiftNetMemoryAllocatorStack* const find_free_pointer_stack(struct SwiftNetMemoryAllocator* const allocator) {
    uint64_t bitmap;
    uint16_t first_free;

    uint64_t invalid_bitmap = 0x00;

    uint64_t new_bitmap;

    struct SwiftNetMemoryAllocatorStack* stack = NULL;

    bitmap = atomic_load_explicit(&allocator->occupied, memory_order_acquire);

    goto find_free_stack;

find_free_stack:
    if((bitmap | invalid_bitmap) == UINT64_MAX) {
        return NULL;
    } else {
        first_free = __builtin_ctz(bitmap | invalid_bitmap);
    }

    if (first_free >= allocator->stacks_allocated) {
        return NULL;
    }

    new_bitmap = bitmap | (1ULL << first_free);

    if (!atomic_compare_exchange_strong_explicit(&allocator->occupied, &bitmap, new_bitmap, memory_order_release, memory_order_acquire)) {
        goto find_free_stack;
    }

    stack = allocator->stacks[first_free];

    goto process_stack;

process_stack:
    if (atomic_load(&stack->size) <= allocator->chunk_item_amount) {
        return stack;
    } else {
        free_stack_lock(stack, allocator);

        invalid_bitmap = invalid_bitmap | (1ULL << first_free);

        goto find_free_stack;
    }

    return NULL;
}

struct SwiftNetMemoryAllocator allocator_create(const uint32_t item_size, const uint32_t chunk_item_amount) {
    void* const allocated_memory = malloc(item_size * chunk_item_amount);
    void* const pointers_memory = malloc(chunk_item_amount * sizeof(void*));

    if (unlikely(allocated_memory == NULL || pointers_memory == NULL)) {
        PRINT_ERROR("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    struct SwiftNetMemoryAllocatorStack* const first_stack = malloc(sizeof(struct SwiftNetMemoryAllocatorStack));
    if (unlikely(first_stack == NULL)) {
        PRINT_ERROR("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    first_stack->data = allocated_memory;
    first_stack->pointers = pointers_memory;
    first_stack->size = chunk_item_amount;
    first_stack->index = 0;

    struct SwiftNetMemoryAllocator new_allocator = (struct SwiftNetMemoryAllocator){
        .item_size = item_size,
        .chunk_item_amount = chunk_item_amount,
        .stacks_allocated = 1
    };

    memset(&new_allocator.stacks, 0x00, sizeof(void*) * 64);

    new_allocator.stacks[0] = first_stack;

    atomic_store_explicit(&new_allocator.occupied, 0x00, memory_order_release);

    for (uint32_t i = 0; i < chunk_item_amount; i++) {
        (*((void **)pointers_memory + i) = (uint8_t*)allocated_memory + (i * item_size));
    }

    atomic_store_explicit(&new_allocator.creating_stack, STACK_CREATING_UNLOCKED, memory_order_release);

    #ifdef SWIFT_NET_INTERNAL_TESTING
        atomic_store_explicit(&first_stack->accessing_ptr_status, false, memory_order_release);
        first_stack->ptr_status = calloc(sizeof(uint8_t), (chunk_item_amount / 8) + 1);
    #endif

    return new_allocator;
}

static void create_new_stack(struct SwiftNetMemoryAllocator* const memory_allocator) {
    uint8_t creating_unlocked = STACK_CREATING_UNLOCKED;

    while (!atomic_compare_exchange_strong_explicit(&memory_allocator->creating_stack, &creating_unlocked, STACK_CREATING_LOCKED, memory_order_acquire, memory_order_relaxed)) {
        creating_unlocked = STACK_CREATING_UNLOCKED;

        usleep(100);

        continue;
    }

    const uint32_t chunk_item_amount = memory_allocator->chunk_item_amount;
    const uint32_t item_size = memory_allocator->item_size;

    void* const allocated_memory = malloc(memory_allocator->item_size * chunk_item_amount);
    void* const allocated_memory_pointers = malloc(chunk_item_amount * sizeof(void*));
    if (unlikely(allocated_memory == NULL || allocated_memory_pointers == NULL)) {
        PRINT_ERROR("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    struct SwiftNetMemoryAllocatorStack* const stack = malloc(sizeof(struct SwiftNetMemoryAllocatorStack));
    if (unlikely(stack == NULL)) {
        PRINT_ERROR("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    stack->pointers = allocated_memory_pointers;
    stack->data = allocated_memory;
    stack->size = chunk_item_amount;
    stack->index = memory_allocator->stacks_allocated;

    for (uint32_t i = 0; i < chunk_item_amount; i++) {
        ((void **)allocated_memory_pointers)[i] = (uint8_t*)allocated_memory + (i * item_size);
    }

    #ifdef SWIFT_NET_INTERNAL_TESTING
        atomic_store_explicit(&stack->accessing_ptr_status, false, memory_order_release);
        stack->ptr_status = calloc(sizeof(uint8_t), (chunk_item_amount / 8) + 1);
    #endif

    memory_allocator->stacks[memory_allocator->stacks_allocated] = stack;

    memory_allocator->stacks_allocated++;

    atomic_store_explicit(&memory_allocator->creating_stack, STACK_CREATING_UNLOCKED, memory_order_release);
}

void* allocator_allocate(struct SwiftNetMemoryAllocator* const memory_allocator) {
    struct SwiftNetMemoryAllocatorStack* const valid_stack = find_free_pointer_stack(memory_allocator);

    if (valid_stack == NULL) {
        create_new_stack(memory_allocator);

        void* const res = allocator_allocate(memory_allocator);

        return res;
    }

    const uint32_t size = atomic_fetch_add(&valid_stack->size, -1);;

    void** const ptr_to_data = ((void**)valid_stack->pointers) + size - 1;

    void* item_ptr = *ptr_to_data;

    #ifdef SWIFT_NET_INTERNAL_TESTING
        set_memory_status(memory_allocator, item_ptr, 1);
    #endif

    free_stack_lock(valid_stack, memory_allocator);

    return item_ptr;
}

void allocator_free(struct SwiftNetMemoryAllocator* const memory_allocator, void* const memory_location) {
    #ifdef SWIFT_NET_INTERNAL_TESTING
        const bool already_free = is_already_free(memory_allocator, memory_location);

        if (already_free == true) {
            PRINT_ERROR("Pointer %p has already been freed", memory_location);
            exit(EXIT_FAILURE);
        }
    #endif

    struct SwiftNetMemoryAllocatorStack* const free_stack = find_free_pointer_stack(memory_allocator);
    if (free_stack == NULL) {
        create_new_stack(memory_allocator);

        allocator_free(memory_allocator, memory_location);

        return;
    }

    const uint32_t size = atomic_fetch_add(&free_stack->size, 1);

    ((void**)free_stack->pointers)[size] = memory_location;

    #ifdef SWIFT_NET_INTERNAL_TESTING
        set_memory_status(memory_allocator, memory_location, 0);
    #endif

    free_stack_lock(free_stack, memory_allocator);
}

void allocator_destroy(struct SwiftNetMemoryAllocator* const memory_allocator) {
    for (uint32_t stack_index = 0; stack_index < memory_allocator->stacks_allocated; stack_index++) {
        struct SwiftNetMemoryAllocatorStack* const current_stack = memory_allocator->stacks[stack_index];

        free(current_stack->data);
        free(current_stack->pointers);

        #ifdef SWIFT_NET_INTERNAL_TESTING
            lock_ptr_status(current_stack);

            const uint32_t total_items = memory_allocator->chunk_item_amount;
            const uint32_t bytes = (total_items / 8) + 1;

            for (uint32_t byte = 0; byte < bytes; byte++) {
                uint8_t mask = current_stack->ptr_status[byte];

                if (mask == 0x00) {
                    continue;
                }

                for (uint8_t bit = 0; bit < 8; bit++) {
                    uint32_t idx = byte * 8 + bit;
                    if (idx >= total_items) break;

                    bool allocated = (mask & (1u << bit)) != 0;

                    if (allocated) {
                        items_leaked++;
                        bytes_leaked += memory_allocator->item_size;
                    }
                }
            }

            unlock_ptr_status(current_stack);

            free(current_stack->ptr_status);
        #endif

        free(current_stack);
    }
}
