//
// Created by YUAN on 2026/4/17.
//

#ifndef SHELLCODE_HASH_H
#define SHELLCODE_HASH_H

#include <cstdint>

#include "../frame/frame.h"

FRAME_FUNCTION uint32_t ror(const uint32_t n);
FRAME_FUNCTION char upper(const char c);
FRAME_FUNCTION wchar_t wchar_upper(const wchar_t wc);
FRAME_FUNCTION uint32_t ror_hash(const char* name);
FRAME_FUNCTION uint32_t wchar_ror_hash(const wchar_t* name);

#endif //SHELLCODE_HASH_H