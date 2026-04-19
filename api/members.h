//
// Created by YUAN on 2026/4/19.
//

#ifndef SHELLCODE_MEMBERS_H
#define SHELLCODE_MEMBERS_H

#include "basic_members.h"

#if defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__)
    #define ARCHITECTURE_X64 1
#elif defined(__i386__) || defined(_X86_) || defined(__x86__)
    #define ARCHITECTURE_X86 1
#endif

#if defined(ARCHITECTURE_X64)
    #include "members_x64.h"
    typedef IMAGE_OPTIONAL_HEADER_x64 IMAGE_OPTIONAL_HEADER;
    typedef PIMAGE_OPTIONAL_HEADER_x64 PIMAGE_OPTIONAL_HEADER;
    typedef IMAGE_NT_HEADERS_x64 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS_x64 PIMAGE_NT_HEADERS;
#elif defined(ARCHITECTURE_X86)
    #include "members_x86.h"
    typedef IMAGE_OPTIONAL_HEADER_x86 IMAGE_OPTIONAL_HEADER;
    typedef PIMAGE_OPTIONAL_HEADER_x86 PIMAGE_OPTIONAL_HEADER;
    typedef IMAGE_NT_HEADERS_x86 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS_x86 PIMAGE_NT_HEADERS;
#endif

#endif //SHELLCODE_MEMBERS_H