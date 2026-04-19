function(build_shellcode name shellcode_entry)

    add_executable(${name}
            ${ARGN}
            ${CMAKE_CURRENT_SOURCE_DIR}/hash/hash.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/api/api.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/frame_api/frame_api.cpp
    )

    target_compile_options(${name} PRIVATE
            -Os
            -ffreestanding
            -fno-builtin
            -fno-stack-protector
            -fno-exceptions
            -fno-rtti
            -fno-asynchronous-unwind-tables
            -fno-unwind-tables
            -fomit-frame-pointer
            -fPIE
            -falign-functions=1
            -falign-labels=1
            -falign-loops=1
            -falign-jumps=1
    )

    target_link_options(${name} PRIVATE
            -nostdlib
            -pie
            "LINKER:--entry,${shellcode_entry}"
            "LINKER:--gc-sections"
    )

    add_custom_command(TARGET ${name} POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} -O binary
            --only-section=.payload
            $<TARGET_FILE:${name}>
            ${CMAKE_CURRENT_BINARY_DIR}/${name}.bin
            COMMENT "Extracting ${name}.bin"
    )
endfunction()
