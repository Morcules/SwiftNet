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
    bool target;


    target = false;

    goto acquire_lock;


acquire_lock:
    if(atomic_compare_exchange_strong_explicit(
        &stack->accessing_ptr_status,
        &target,
        true,
        memory_order_acquire,
        memory_order_relaxed
    )) {
        return;
    }

    target = false;

    goto acquire_lock;
}

static inline void set_memory_status(struct SwiftNetMemoryAllocator* const memory_allocator, void* const memory_location, const uint8_t status) {
    uint16_t stacks_allocated;
    uint16_t i;


    stacks_allocated = atomic_load_explicit(&memory_allocator->stacks_allocated, memory_order_acquire);

    for(i = 0; i < stacks_allocated; i++) {
        struct SwiftNetMemoryAllocatorStack* stack;
        uint8_t* casted_data;
        uint8_t* casted_memory_loc;
        uint32_t offset;
        uint32_t index;
        uint32_t byte;
        uint8_t bit;


        stack = atomic_load_explicit(&memory_allocator->stacks[i], memory_order_acquire);

        casted_data = stack->data;
        casted_memory_loc = memory_location;

        if(
            casted_memory_loc >= casted_data
            &&
            casted_memory_loc < casted_data + (memory_allocator->item_size * memory_allocator->chunk_item_amount)
        ) {
            offset = casted_memory_loc - casted_data;
            index = offset / memory_allocator->item_size;

            byte = index / 8;
            bit = index % 8;

            lock_ptr_status(stack);

            if(status) {
                *(stack->ptr_status + byte) |= (1u << bit);
            } else {
                *(stack->ptr_status + byte) &= ~(1u << bit);
            }

            unlock_ptr_status(stack);

            return;
        }
    }
}

static inline bool is_already_free(struct SwiftNetMemoryAllocator* const memory_allocator, void* const memory_location) {
    uint16_t stacks_allocated;
    uint16_t i;


    stacks_allocated = atomic_load_explicit(&memory_allocator->stacks_allocated, memory_order_acquire);

    for(i = 0; i < stacks_allocated; i++) {
        struct SwiftNetMemoryAllocatorStack* stack;
        uint8_t* casted_data;
        uint8_t* casted_memory_loc;
        uint32_t offset;
        uint32_t index;
        uint32_t byte;
        uint8_t bit;


        stack = atomic_load_explicit(&memory_allocator->stacks[i], memory_order_acquire);

        casted_data = stack->data;
        casted_memory_loc = memory_location;

        if(
            casted_memory_loc >= casted_data
            &&
            casted_memory_loc < casted_data + (memory_allocator->item_size * memory_allocator->chunk_item_amount)
        ) {
            offset = casted_memory_loc - casted_data;
            index = offset / memory_allocator->item_size;

            byte = index / 8;
            bit = index % 8;

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

// Type is either 0/1 - 1 = allocation - 0 = freeing
struct SwiftNetMemoryAllocatorStack* const find_free_pointer_stack(struct SwiftNetMemoryAllocator* const allocator, const uint8_t type) {
    uint16_t stacks_allocated;
    uint64_t bitmap;
    uint16_t first_free;
    uint64_t invalid_bitmap;
    uint64_t new_bitmap;
    uint32_t stack_size;
    bool valid_size;
    struct SwiftNetMemoryAllocatorStack* stack;


    stacks_allocated = atomic_load_explicit(&allocator->stacks_allocated, memory_order_acquire);

    invalid_bitmap = 0x00;

    bitmap = atomic_load_explicit(&allocator->occupied, memory_order_acquire);

    goto find_free_stack;


find_free_stack:
    if((bitmap | invalid_bitmap) == UINT64_MAX) {
        return NULL;
    } else {
        first_free = __builtin_ctzll(~(bitmap | invalid_bitmap));
    }

    if(first_free >= stacks_allocated) {
        return NULL;
    }

    new_bitmap = bitmap | (1ULL << first_free);

    if(!atomic_compare_exchange_strong_explicit(&allocator->occupied, &bitmap, new_bitmap, memory_order_release, memory_order_acquire)) {
        goto find_free_stack;
    }

    stack = atomic_load_explicit(&allocator->stacks[first_free], memory_order_acquire);

    goto process_stack;


process_stack:
    stack_size = atomic_load_explicit(&stack->size, memory_order_acquire);

    valid_size = type == 0 ? (stack_size < allocator->chunk_item_amount && stack_size >= 0) : (stack_size <= allocator->chunk_item_amount && stack_size > 0);

    if(valid_size) {
        return stack;
    } else {
        free_stack_lock(stack, allocator);

        invalid_bitmap = invalid_bitmap | (1ULL << first_free);

        goto find_free_stack;
    }
}

struct SwiftNetMemoryAllocator allocator_create(const uint32_t item_size, const uint32_t chunk_item_amount) {
    void* allocated_memory;
    void* pointers_memory;
    struct SwiftNetMemoryAllocatorStack* first_stack;
    struct SwiftNetMemoryAllocator new_allocator;
    uint32_t i;


    allocated_memory = malloc(item_size * chunk_item_amount);
    pointers_memory = malloc(chunk_item_amount * sizeof(void*));

    if(unlikely(allocated_memory == NULL || pointers_memory == NULL)) {
        PRINT_ERROR("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    first_stack = malloc(sizeof(struct SwiftNetMemoryAllocatorStack));
    if(unlikely(first_stack == NULL)) {
        PRINT_ERROR("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    first_stack->data = allocated_memory;
    first_stack->pointers = pointers_memory;
    first_stack->size = chunk_item_amount;
    first_stack->index = 0;

    new_allocator = (struct SwiftNetMemoryAllocator){
        .item_size = item_size,
        .chunk_item_amount = chunk_item_amount,
        .stacks_allocated = 1
    };

    memset(&new_allocator.stacks, 0x00, sizeof(void*) * 64);

    new_allocator.stacks[0] = first_stack;

    atomic_store_explicit(&new_allocator.occupied, 0x00, memory_order_release);

    for(i = 0; i < chunk_item_amount; i++) {
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
    uint8_t creating_unlocked;
    uint32_t chunk_item_amount;
    uint32_t item_size;
    void* allocated_memory;
    void* allocated_memory_pointers;
    struct SwiftNetMemoryAllocatorStack* stack;
    uint16_t stacks_allocated;
    uint32_t i;


    creating_unlocked = STACK_CREATING_UNLOCKED;

    goto acquire_creating_lock;


acquire_creating_lock:
    if(atomic_compare_exchange_strong_explicit(&memory_allocator->creating_stack, &creating_unlocked, STACK_CREATING_LOCKED, memory_order_release, memory_order_relaxed)) {
        goto allocate_stack;
    }

    creating_unlocked = STACK_CREATING_UNLOCKED;

    usleep(100);

    goto acquire_creating_lock;


allocate_stack:
    chunk_item_amount = memory_allocator->chunk_item_amount;
    item_size = memory_allocator->item_size;

    allocated_memory = malloc(memory_allocator->item_size * chunk_item_amount);
    allocated_memory_pointers = malloc(chunk_item_amount * sizeof(void*));
    if(unlikely(allocated_memory == NULL || allocated_memory_pointers == NULL)) {
        PRINT_ERROR("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    stack = malloc(sizeof(struct SwiftNetMemoryAllocatorStack));
    if(unlikely(stack == NULL)) {
        PRINT_ERROR("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    stacks_allocated = atomic_load_explicit(&memory_allocator->stacks_allocated, memory_order_acquire);

    stack->pointers = allocated_memory_pointers;
    stack->data = allocated_memory;
    stack->size = chunk_item_amount;
    stack->index = stacks_allocated;

    for(i = 0; i < chunk_item_amount; i++) {
        ((void **)allocated_memory_pointers)[i] = (uint8_t*)allocated_memory + (i * item_size);
    }

    #ifdef SWIFT_NET_INTERNAL_TESTING
        atomic_store_explicit(&stack->accessing_ptr_status, false, memory_order_release);
        stack->ptr_status = calloc(sizeof(uint8_t), (chunk_item_amount / 8) + 1);
    #endif

    atomic_store_explicit(&memory_allocator->stacks[stacks_allocated], stack, memory_order_release);

    atomic_fetch_add_explicit(&memory_allocator->stacks_allocated, 1, memory_order_release);

    atomic_store_explicit(&memory_allocator->creating_stack, STACK_CREATING_UNLOCKED, memory_order_release);
}

void* allocator_allocate(struct SwiftNetMemoryAllocator* const memory_allocator) {
    struct SwiftNetMemoryAllocatorStack* valid_stack;
    uint32_t size;
    void** ptr_to_data;
    void* item_ptr;
    void* res;


    valid_stack = find_free_pointer_stack(memory_allocator, 1);
    
    if(valid_stack == NULL) {
        create_new_stack(memory_allocator);

        res = allocator_allocate(memory_allocator);

        return res;
    }

    size = atomic_fetch_sub(&valid_stack->size, 1);

    ptr_to_data = ((void**)valid_stack->pointers) + size - 1;

    item_ptr = *ptr_to_data;

    #ifdef SWIFT_NET_INTERNAL_TESTING
        set_memory_status(memory_allocator, item_ptr, 1);
    #endif

    free_stack_lock(valid_stack, memory_allocator);

    return item_ptr;
}

void allocator_free(struct SwiftNetMemoryAllocator* const memory_allocator, void* const memory_location) {
    struct SwiftNetMemoryAllocatorStack* free_stack;
    uint32_t size;
    bool already_free;


    #ifdef SWIFT_NET_INTERNAL_TESTING
        already_free = is_already_free(memory_allocator, memory_location);

        if(already_free == true) {
            PRINT_ERROR("Pointer %p has already been freed", memory_location);
            exit(EXIT_FAILURE);
        }
    #endif

    free_stack = find_free_pointer_stack(memory_allocator, 0);
    if(free_stack == NULL) {
        create_new_stack(memory_allocator);

        allocator_free(memory_allocator, memory_location);

        return;
    }

    size = atomic_fetch_add(&free_stack->size, 1);

    ((void**)free_stack->pointers)[size] = memory_location;

    #ifdef SWIFT_NET_INTERNAL_TESTING
        set_memory_status(memory_allocator, memory_location, 0);
    #endif

    free_stack_lock(free_stack, memory_allocator);
}

void allocator_destroy(struct SwiftNetMemoryAllocator* const memory_allocator
    #ifdef SWIFT_NET_INTERNAL_TESTING
        , const bool disable_internal_check
    #endif
) {
    uint16_t stacks_allocated;
    uint16_t stack_index;


    stacks_allocated = atomic_load_explicit(&memory_allocator->stacks_allocated, memory_order_acquire);

    for(stack_index = 0; stack_index < stacks_allocated; stack_index++) {
        struct SwiftNetMemoryAllocatorStack* current_stack;


        current_stack = atomic_load_explicit(&memory_allocator->stacks[stack_index], memory_order_acquire);

        free(current_stack->data);
        free(current_stack->pointers);

        #ifdef SWIFT_NET_INTERNAL_TESTING
            if(!disable_internal_check) {
                uint32_t total_items;
                uint32_t bytes;
                uint32_t byte;
                uint8_t bit;
                uint32_t idx;
                bool allocated;
                uint8_t mask;


                lock_ptr_status(current_stack);

                total_items = memory_allocator->chunk_item_amount;
                bytes = (total_items / 8) + 1;

                for(byte = 0; byte < bytes; byte++) {
                    mask = current_stack->ptr_status[byte];

                    if(mask == 0x00) {
                        continue;
                    }

                    for(bit = 0; bit < 8; bit++) {
                        idx = byte * 8 + bit;
                        if(idx >= total_items) {
                            break;
                        }

                        allocated = (mask & (1u << bit)) != 0;

                        if(allocated) {
                            items_leaked++;
                            bytes_leaked += memory_allocator->item_size;
                        }
                    }
                }

                unlock_ptr_status(current_stack);
            }

            free(current_stack->ptr_status);
        #endif

        free(current_stack);
    }
}