#pragma once
#include <cstdint>

// FNV-1a Hash (Calculated during compilation)
constexpr uint32_t HashString(const char* str) {
    uint32_t hash = 0x811c9dc5;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 0x01000193;
    }
    return hash;
}

// Now you can find functions by comparing 0xDEADBEEF instead of "NtWrite"
