//
// Created by YUAN on 2026/4/17.
//

#ifndef SHELLCODE_API_H
#define SHELLCODE_API_H

#include <cstdint>

#include "members.h"
#include "../frame/frame_basic_macro.h"

FRAME_FUNCTION PPEB get_ppeb();
FRAME_FUNCTION void* get_module_base_address(uint32_t module_name_hash);
FRAME_FUNCTION void* get_function_address_by_hash(const uint32_t module_name_hash, const uint32_t function_name_hash);
FRAME_FUNCTION void* get_function_address(const char* module_name, const char* function_name);

#endif //SHELLCODE_API_H