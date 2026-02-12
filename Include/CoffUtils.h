#pragma once

#include <windows.h>
#include "CoffHeaders.h"

#define IMPORT_PATTERN_SIZE 0x6
#define	IAT_TABLE_SIZE		0x2000

typedef struct _SYMBOL_INFORMATION {
	LPSTR lpFunctionName;  
	LPSTR lpModuleName;    
} SYMBOL_INFORMATION, *PSYMBOL_INFORMATION;

typedef struct _COFF_LOADER_CONTEXT
{
	PVOID           hHeap;
	PVOID           pCoffContent;       
	DWORD           dwCoffSize;         

	PCOFF_FILE_HEADER pCoffFileHeader;  
	PCOFF_MEM_SECTION pMemSections;    
	PCOFF_SYM_ADDR    pMemSymbols;      
	PCOFF_SYMBOL      pCoffSymTable;    
	PBYTE             pStringTable;     

	PBYTE           pIatTable;          
	DWORD           dwIatIndex;        

	void*           pEntryPoint;       
} COFF_LOADER_CONTEXT, *PCOFF_LOADER_CONTEXT;

