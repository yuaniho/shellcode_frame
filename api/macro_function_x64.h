//
// Created by YUAN on 2026/4/17.
//

#ifndef SHELLCODE_MACRO_FUNCTION_x64_H
#define SHELLCODE_MACRO_FUNCTION_x64_H

#if defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__)

#include "basic_macro.h"

#if FRAME_INTRINSIC_PROLOG(frame_readgsqword)

FRAME_MINGW_EXTENSION FRAME_UNSIGNED_INT_64 frame_readgsqword(FRAME_UNSIGNED_LONG32 Offset);

#if !__has_builtin(frame_readgsqword)
FRAME_MINGW_EXTENSION FRAME_INTRINSICS_USEINLINE
frame_buildreadseg(frame_readgsqword, FRAME_UNSIGNED_INT_64, "gs", "q")
#endif

#define __INTRINSIC_DEFINED_frame_readgsqword

#endif /* FRAME_INTRINSIC_PROLOG */

#endif

#endif //SHELLCODE_MACRO_FUNCTION_x64_H