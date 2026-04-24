//
// Created by YUAN on 2026/4/18.
//

// 定义框架的全局基本宏

#ifndef SHELLCODE_FRAME_BASIC_MACRO_H
#define SHELLCODE_FRAME_BASIC_MACRO_H

#include <cstddef>
#include <cstdint>

#define WINAPI __stdcall
#define CAPI __cdecl
#define FASTAPI __fastcall

#define PAYLOAD_SEGMENT __attribute__((section(".payload")))
#define SEGMENT_ENTRY __attribute__((section(".payload.entry")))

#define EXTERN_C extern "C"

#define FRAME_FUNCTION EXTERN_C PAYLOAD_SEGMENT

#define SHELLCODE_ENTRY EXTERN_C SEGMENT_ENTRY

#endif //SHELLCODE_FRAME_BASIC_MACRO_H