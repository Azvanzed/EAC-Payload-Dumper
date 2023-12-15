#include "utils.h"
#include <stdbool.h>
#include <string.h>
#include <windows.h>

uint64_t find_pattern(uint64_t start, size_t size, const char* pattern, const char* mask) {
    size_t length = strlen(mask);
    for (size_t i = 0; i < size - length; ++i) {
        for (size_t j = 0; j < length; ++j) {
            if (mask[j] != '?' && pattern[j] != *(char*)(start + i + j)) {
                break;
            }
            else if (j == length - 1) {
                return start + i;
            }
        }
    }

    return 0;
}

bool set_bytes(void* dst, uint8_t val, size_t size) {
    DWORD old_protect;
    if (!VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }

    memset(dst, val, size);
    return VirtualProtect(dst, size, old_protect, &old_protect) == TRUE;
}

void save_dump(const char* name, void* data, size_t size) {
    FILE* file = fopen(name, "wb");
    ASSERT(file != NULL);

    ASSERT(fwrite(data, 1, size, file) == size);
    ASSERT(fclose(file) == 0);
}