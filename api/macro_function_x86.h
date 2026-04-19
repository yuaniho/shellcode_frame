//
// Created by YUAN on 2026/4/18.
//

#ifndef SHELLCODE_MACRO_FUNCTION_X86_H
#define SHELLCODE_MACRO_FUNCTION_X86_H

#if defined(__i386__) || defined(_X86_) || defined(__x86__)

#include "basic_macro.h"

#undef FRAME_INTRINSICS_USEINLINE
#ifdef __INTRINSIC_ONLYSPECIAL
#  define FRAME_INTRINSICS_USEINLINE
#else
#  define FRAME_INTRINSICS_USEINLINE FRAME_MINGW_INTRIN_INLINE
#endif

#if FRAME_INTRINSIC_PROLOG(frame_readfsdword)

UNSIGNED_LONG32 frame_readfsdword(UNSIGNED_LONG32 Offset);

#if !__has_builtin(frame_readfsdword)
FRAME_INTRINSICS_USEINLINE
frame_buildreadseg(frame_readfsdword, UNSIGNED_LONG32, "fs", "l")
#endif

#define __INTRINSIC_DEFINED_frame_readfsdword

#endif /* __INTRINSIC_PROLOG */

#endif

#endif //SHELLCODE_MACRO_FUNCTION_X86_H