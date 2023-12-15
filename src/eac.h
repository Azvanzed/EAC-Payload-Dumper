#ifndef H_EAC
#define H_EAC

#include <stdint.h>

void decrypt_module(uint8_t* block, uint32_t size);

#define EAC_CALL_PATTERN "\xE8\xCC\xCC\xCC\xCC\x48\x8B\x44\x24\x48\x8B\x8C\x24\x78\x02\x00\x00\x89\x88\x30\x02\x00\x00\x8B\x84\x24\x78\x02\x00\x00"
#define EAC_CALL_MASK "x????xxxxxxxxxxxxxxxxxxxxxxxxx"

#endif