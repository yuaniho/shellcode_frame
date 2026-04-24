//
// Created by YUAN on 2026/4/17.
//

#include "api.h"
#include "members.h"
#include "../hash/hash.h"
#include "macro_function.h"

PPEB get_ppeb() {
    PPEB ppeb;
#ifndef _WIN64
    ppeb = reinterpret_cast<PPEB>(frame_readfsdword(0x30));
#else
    ppeb = reinterpret_cast<PPEB>(frame_readgsqword(0x60));
#endif
    return ppeb;
}

void* get_module_base_address(uint32_t module_name_hash) {
    PPEB ppeb = get_ppeb();
    const LIST_ENTRY* head = &ppeb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current = head->Flink;

    while (current != head) {
        uint8_t* ldr_data_table_entry_head = reinterpret_cast<uint8_t*>(current)  - 0x10;
        const UNICODE_STRING* dll_name_struct = reinterpret_cast<UNICODE_STRING*>(ldr_data_table_entry_head + 0x58);

        if (dll_name_struct && dll_name_struct->Buffer) {
            uint32_t dll_name_hash = wchar_ror_hash(dll_name_struct->Buffer);
            if (dll_name_hash == module_name_hash) {
                return *reinterpret_cast<void**>(ldr_data_table_entry_head + 0x30);
            }
            current = current->Flink;
        }
    }
    return nullptr;
}

void* get_function_address_by_hash(const uint32_t module_name_hash, const uint32_t function_name_hash) {
    void* module_base_address = get_module_base_address(module_name_hash);

    if (!module_base_address) {
        return nullptr;
    }

    uint8_t* base = static_cast<uint8_t*>(module_base_address);

    const IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    const IMAGE_NT_HEADERS* nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos_header->e_lfanew);
    const IMAGE_EXPORT_DIRECTORY* export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        base + nt_header->OptionalHeader.DataDirectory[0].VirtualAddress);

    if (!export_directory) {
        return nullptr;
    }

    const uint32_t* names_array_va_address = reinterpret_cast<uint32_t*>(base + export_directory->AddressOfNames);
    const uint32_t* function_array_va_address = reinterpret_cast<uint32_t*>(base + export_directory->AddressOfFunctions);
    const uint16_t* name_ordinals_array_va_address = reinterpret_cast<uint16_t*>(base + export_directory->AddressOfNameOrdinals);

    for (uint32_t i = 0; i < export_directory->NumberOfNames; i++) {
        const char* function_name = reinterpret_cast<char*>(base + names_array_va_address[i]);
        if (ror_hash(function_name) == function_name_hash) {
            return base + function_array_va_address[name_ordinals_array_va_address[i]];
        }
    }
    return nullptr;
}

void* get_function_address(const char* module_name, const char* function_name) {
    return get_function_address_by_hash(ror_hash(module_name), ror_hash(function_name));
}