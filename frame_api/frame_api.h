//
// Created by YUAN on 2026/4/18.
//

#ifndef SHELLCODE_FRAME_API_H
#define SHELLCODE_FRAME_API_H

#include "../frame/frame.h"

FRAME_FUNCTION void frame_memcpy(void* dst, void* src, size_t size);
FRAME_FUNCTION void frame_memset(void* dst, const uint8_t value, size_t size);

#endif //SHELLCODE_FRAME_API_H