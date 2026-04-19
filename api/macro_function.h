//
// Created by YUAN on 2026/4/18.
//

#ifndef SHELLCODE_MACRO_FUNCTION_H
#define SHELLCODE_MACRO_FUNCTION_H

#if defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__)
#include "macro_function_x64.h"
#elif defined(__i386__) || defined(_X86_) || defined(__x86__)
#include "macro_function_x86.h"
#endif

#endif //SHELLCODE_MACRO_FUNCTION_H