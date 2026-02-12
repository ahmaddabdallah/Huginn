#pragma once

#include <windows.h>

#define MEM_SYMNAME_MAX		100

typedef struct _COFF_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} COFF_FILE_HEADER, *PCOFF_FILE_HEADER;


#pragma pack(push,1)
typedef struct _COFF_SECTION {
    CHAR Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLineNumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} COFF_SECTION, *PCOFF_SECTION;


typedef struct _COFF_RELOCATION {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD Type;
} COFF_RELOCATION, *PCOFF_RELOCATION;


typedef struct _COFF_SYMBOL {
    union {
        CHAR ShortName[8];
        struct {
            DWORD Zeros;
            DWORD Offset;
        };
    } first;
    DWORD Value;
    WORD SectionNumber;
    WORD Type;
    BYTE StorageClass;
    BYTE NumberOfAuxSymbols;
} COFF_SYMBOL, *PCOFF_SYMBOL;


typedef struct _COFF_MEM_SECTION {
    DWORD	Counter;
    CHAR		Name[10];
    DWORD	SizeOfRawData;
    DWORD	PointerToRawData;
    DWORD	PointerToRelocations;
    WORD	NumberOfRelocations;
    DWORD	Characteristics;
    UINT_PTR	InMemoryAddress;
    DWORD	InMemorySize;	
} COFF_MEM_SECTION, *PCOFF_MEM_SECTION;


typedef struct _COFF_SYM_ADDR {
    DWORD	Counter;
    CHAR		Name[MEM_SYMNAME_MAX];
    WORD	SectionNumber;
    DWORD	Value;
    BYTE		StorageClass;
    UINT_PTR	InMemoryAddress;
    UINT_PTR	GOTaddress;
} COFF_SYM_ADDR, *PCOFF_SYM_ADDR;
#pragma pack(pop)

#define MACHINETYPE_AMD64 0x8664

// Bug fix : suppression du define IMAGE_SCN_CNT_CODE duplique (deja defini ligne 127)

#define IMAGE_REL_AMD64_ABSOLUTE    0x0000
#define IMAGE_REL_AMD64_ADDR64      0x0001
#define IMAGE_REL_AMD64_ADDR32      0x0002
#define IMAGE_REL_AMD64_ADDR32NB    0x0003

#define IMAGE_REL_AMD64_REL32       0x0004

#define IMAGE_REL_AMD64_REL32_1     0x0005
#define IMAGE_REL_AMD64_REL32_2     0x0006
#define IMAGE_REL_AMD64_REL32_3     0x0007
#define IMAGE_REL_AMD64_REL32_4     0x0008
#define IMAGE_REL_AMD64_REL32_5     0x0009
#define IMAGE_REL_AMD64_SECTION     0x000A
#define IMAGE_REL_AMD64_SECREL      0x000B
#define IMAGE_REL_AMD64_SECREL7     0x000C
#define IMAGE_REL_AMD64_TOKEN       0x000D
#define IMAGE_REL_AMD64_SREL32      0x000E
#define IMAGE_REL_AMD64_PAIR        0x000F
#define IMAGE_REL_AMD64_SSPAN32     0x0010

#define IMAGE_REL_I386_ABSOLUTE     0x0000
#define IMAGE_REL_I386_DIR16        0x0001
#define IMAGE_REL_I386_REL16        0x0002
#define IMAGE_REL_I386_DIR32        0x0006
#define IMAGE_REL_I386_DIR32NB      0x0007
#define IMAGE_REL_I386_SEG12        0x0009
#define IMAGE_REL_I386_SECTION      0x000A
#define IMAGE_REL_I386_SECREL       0x000B
#define IMAGE_REL_I386_TOKEN        0x000C
#define IMAGE_REL_I386_SECREL7      0x000D
#define IMAGE_REL_I386_REL32        0x0014

#define IMAGE_SCN_MEM_WRITE					0x80000000
#define IMAGE_SCN_MEM_READ					0x40000000
#define IMAGE_SCN_MEM_EXECUTE				0x20000000
#define IMAGE_SCN_ALIGN_16BYTES				0x00500000
#define IMAGE_SCN_MEM_NOT_CACHED			0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED				0x08000000
#define IMAGE_SCN_MEM_SHARED				0x10000000
#define IMAGE_SCN_CNT_CODE					0x00000020
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA	0x00000080
#define IMAGE_SCN_MEM_DISCARDABLE			0x02000000
