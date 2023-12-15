#ifndef H_UTILS
#define H_UTILS

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

uint64_t find_pattern(uint64_t start, size_t size, const char* pattern, const char* mask);
bool set_bytes(void* dst, uint8_t val, size_t size);
void save_dump(const char* name, void* data, size_t size);

#define ASSERT(x) if (!(x)) { printf("[%i] assertion failed: %s\n", __LINE__, #x); abort(); }

#endif