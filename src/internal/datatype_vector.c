#include "internal.h"
#include <stdatomic.h>
#include <stdint.h>

struct SwiftNetVector vector_create(const uint32_t starting_amount) {
    void* data_ptr;


    data_ptr = malloc(sizeof(void*) * starting_amount);
    if(unlikely(data_ptr == NULL)) {
        PRINT_ERROR("Failed to malloc");
        exit(EXIT_FAILURE);
    }

    return (struct SwiftNetVector){
        .size = 0,
        .capacity = starting_amount,
        .data = data_ptr,
        .locked = 0
    };
}

void vector_destroy(struct SwiftNetVector* const vector) {
    free(vector->data);
}

void vector_push(struct SwiftNetVector* const vector, void* const data) {
    uint32_t size;
    uint32_t capacity;
    uint32_t new_capacity;
    void** new_data_ptr;


    size = vector->size;
    capacity = vector->capacity;

    if(size == capacity) {
        new_capacity = capacity * 2;

        vector->capacity = new_capacity;

        new_data_ptr = realloc(vector->data, sizeof(void*) * new_capacity);
        if(unlikely(new_data_ptr == NULL)) {
            PRINT_ERROR("Failed to malloc");
            exit(EXIT_FAILURE);
        }

        vector->data = new_data_ptr;
    }

    *((vector->data) + size) = data;

    vector->size++;
}

void vector_remove(struct SwiftNetVector* const vector, const uint32_t index) {
    if(index < vector->size - 1) {
        memcpy(vector->data + index, vector->data + vector->size - 1, sizeof(void*));
    }

    vector->size--;
}

void* vector_get(struct SwiftNetVector* const vector, const uint32_t index) {
    void** data_ptr;


    data_ptr = ((void**)vector->data) + index;

    return *data_ptr;
}