//
// Created by YUAN on 2026/4/18.
//

#ifndef SHELLCODE_BASIC_MACRO_H
#define SHELLCODE_BASIC_MACRO_H

#include "../frame/frame_basic_macro.h"

#include <cstddef>
#include <cstdint>

#define FRAME_UNSIGNED_LONG32 uint32_t
#define FRAME_UNSIGNED_INT_64 uint64_t

#define FRAME_INTRINSIC_PROLOG(name) (!defined(__INTRINSIC_DEFINED_ ## name)) && ((!defined (__INTRINSIC_ONLYSPECIAL)) || (defined (__INTRINSIC_ONLYSPECIAL) && defined(__INTRINSIC_SPECIAL_ ## name)))

#ifdef __WIDL__
#  define FRAME_MINGW_EXTENSION
#else
#  if defined(__GNUC__) || defined(__GNUG__)
#    define FRAME_MINGW_EXTENSION __extension__
#  else
#    define FRAME_MINGW_EXTENSION
#  endif
#endif

#define FRAME_C89_NAMELESS FRAME_MINGW_EXTENSION

#define FRAME_MINGW_INTRIN_INLINE extern __inline__ __attribute__((__always_inline__,__gnu_inline__))
#define FRAME_INTRINSICS_USEINLINE FRAME_MINGW_INTRIN_INLINE

#define frame_buildreadseg(x, y, z, a) y x(FRAME_UNSIGNED_LONG32 Offset) { \
    y ret; \
    __asm__ ("mov{" a " %%" z ":%[offset], %[ret] | %[ret], %%" z ":%[offset]}" \
    : [ret] "=r" (ret) \
    : [offset] "m" ((*(y *) (size_t) Offset))); \
    return ret; \
}

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#endif //SHELLCODE_BASIC_MACRO_H