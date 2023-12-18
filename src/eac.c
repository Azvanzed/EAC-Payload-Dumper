#include "eac.h"

// @bright
void decrypt_module(uint8_t* block, uint32_t size) {
    block[size - 1] += 3 - 3 * size;

    for (int32_t i = size - 2; i > 0; --i) {
        block[i] += -3 * i - block[i + 1];
    }

    block[0] -= block[1];
}
