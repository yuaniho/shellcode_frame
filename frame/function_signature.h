//
// Created by YUAN on 2026/4/18.
//

// 定义函数签名头文件，保存函数签名

#ifndef SHELLCODE_FUNCTION_SIGNATURE_H
#define SHELLCODE_FUNCTION_SIGNATURE_H

#include "frame_basic_macro.h"

typedef int (WINAPI *fn_message_box_a)(
    void*,
    const char*,
    const char*,
    uint32_t
);

typedef void* (WINAPI *fn_load_library_a)(
    const char*
);

typedef void (WINAPI *fn_sleep)(
    uint32_t
);

typedef void* (WINAPI *fn_win_http_open)(
    const wchar_t*,
    uint32_t,
    const wchar_t*,
    const wchar_t*,
    uint32_t
);

typedef void* (WINAPI *fn_win_http_connect)(
    void*,
    const wchar_t*,
    uint16_t,
    uint32_t
);

typedef void* (WINAPI *fn_win_http_open_request)(
    void*,
    const wchar_t*,
    const wchar_t*,
    const wchar_t*,
    const wchar_t*,
    const wchar_t**,
    uint32_t
);

typedef int (WINAPI *fn_win_http_send_request)(
    void*,
    const wchar_t*,
    uint32_t,
    void*,
    uint32_t,
    uint32_t,
    uintptr_t
);

typedef int (WINAPI *fn_win_http_receive_response)(
    void*,
    void*
);

typedef int (WINAPI *fn_win_http_query_data_available)(
    void*,
    uint32_t*
);

typedef int (WINAPI *fn_win_http_read_data)(
    void*,
    void*,
    uint32_t,
    uint32_t*
);

typedef int (WINAPI *fn_win_http_close_handle)(
    void*
);

typedef int (WINAPI *fn_virtual_free)(
    void*,
    size_t,
    uint32_t
);

typedef void* (WINAPI *fn_virtual_alloc)(
    void*,
    size_t,
    uint32_t,
    uint32_t
);

typedef int (WINAPI *fn_virtual_protect)(
    void*,
    size_t,
    uint32_t,
    uint32_t*
);

#endif //SHELLCODE_FUNCTION_SIGNATURE_H