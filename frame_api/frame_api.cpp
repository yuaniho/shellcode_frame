//
// Created by YUAN on 2026/4/18.
//

#include "frame_api.h"

void frame_memcpy(void* dst, void* src, size_t size) {
    auto dst8 = static_cast<uint8_t *>(dst);
    auto src8 = static_cast<const uint8_t *>(src);
    while (size--) {
        *dst8++ = *src8++;
    }
}

void frame_memset(void* dst, const uint8_t value, size_t size) {
    auto dst8 = static_cast<uint8_t *>(dst);
    while (size--) {
        *dst8++ = value;
    }
}
