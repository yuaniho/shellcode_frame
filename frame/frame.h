//
// Created by YUAN on 2026/4/18.
//

#ifndef SHELLCODE_FRAME_H
#define SHELLCODE_FRAME_H

#include <cstddef>
#include <cstdint>

#define WINAPI __stdcall

#define PAYLOAD_SEGMENT __attribute__((section(".payload")))

#define EXTERN_C extern "C"

#define FRAME_FUNCTION EXTERN_C PAYLOAD_SEGMENT

#endif //SHELLCODE_FRAME_H