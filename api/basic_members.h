//
// Created by YUAN on 2026/4/19.
//

#ifndef SHELLCODE_BASIC_MEMBERS_H
#define SHELLCODE_BASIC_MEMBERS_H

#include "basic_macro.h"

typedef void (WINAPI *pps_post_process_init_runtime)(void);

typedef struct unicode_string_struct {
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING;

typedef struct list_entry_struct {
    struct list_entry_struct *Flink;
    struct list_entry_struct *Blink;
} LIST_ENTRY;

typedef struct peb_ldr_data_struct {
    uint8_t Reserved1[8];
    void* Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct rtl_user_process_parameters_struct {
    uint8_t Reserved1[16];
    void* Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} *PRTL_USER_PROCESS_PARAMETERS;

typedef struct ldr_data_table_entry_struct {
    void* Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    void* Reserved2[2];
    void* DllBase;
    void* Reserved3[2];
    UNICODE_STRING FullDllName;
    uint8_t Reserved4[8];
    void* Reserved5[3];
    FRAME_C89_NAMELESS union {
        uint32_t CheckSum;
        void* Reserved6;
    };
    uint32_t TimeDateStamp;
} LDR_DATA_TABLE_ENTRY,*PLDR_DATA_TABLE_ENTRY;

typedef struct peb_struct {
    uint8_t Reserved1[2];
    uint8_t BeingDebugged;
    uint8_t Reserved2[1];
    void* Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    void* Reserved4[3];
    void* AtlThunkSListPtr;
    void* Reserved5;
    uint32_t Reserved6;
    void* Reserved7;
    uint32_t Reserved8;
    uint32_t AtlThunkSListPtr32;
    void* Reserved9[45];
    uint8_t Reserved10[96];
    pps_post_process_init_runtime PostProcessInitRoutine;
    uint8_t Reserved11[128];
    void* Reserved12[1];
    uint32_t SessionId;
} PEB, *PPEB;

typedef struct image_dos_header_struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t e_lfanew;
} IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;

typedef struct image_file_header_struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER,*PIMAGE_FILE_HEADER;

typedef struct image_data_directory_struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;

typedef struct image_export_directory_struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

#endif //SHELLCODE_BASIC_MEMBERS_H
