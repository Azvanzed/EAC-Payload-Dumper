#include "eac.h"

// @bright
void decrypt_module(uint8_t* block, uint32_t size) {
    block[size - 1] += 3 - 3 * size;

    uint32_t new_size = size - 2;
    while (new_size > 0) {
        block[new_size] += -3 * new_size - block[new_size + 1];
        --new_size;
    }
    
    block[0] -= block[1];
}