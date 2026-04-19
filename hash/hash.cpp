//
// Created by YUAN on 2026/4/17.
//

#include <cstdint>

#include "hash.h"

#define MOVE_BIT 13

uint32_t ror(const uint32_t n) {
    return (n >> MOVE_BIT) | (n << (32 - MOVE_BIT));
}

char upper(const char c) {
    return (c >= 'a') ? (c - ('a' - 'A')) : c;
}

wchar_t wchar_upper(const wchar_t wc) {
    return (wc >= L'a' && wc <= L'z') ? wc - 32 : wc;
}

uint32_t ror_hash(const char* name) {
    uint32_t hash = 0;
    while (*name) {
        hash = ror(hash);
        const uint8_t c = static_cast<uint8_t>(upper(*name++));
        hash += c;
    }
    return hash;
}

uint32_t wchar_ror_hash(const wchar_t* name) {
    uint32_t hash = 0;
    while (*name) {
        hash = ror(hash);
        const uint8_t c = static_cast<uint8_t>(wchar_upper(*name++));
        hash += c;
    }
    return hash;
}
