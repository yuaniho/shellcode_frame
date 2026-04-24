cmake_minimum_required(VERSION 4.1)
project(shellcode)

set(CMAKE_CXX_STANDARD 20)

include(frame/frame_cmake.cmake)

build_shellcode(stager_shellcode
                shellcode.cpp
)
