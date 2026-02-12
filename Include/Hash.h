#pragma once

#include <windows.h>
#include "Macros.h"

constexpr DWORD ctime_HashStringA(
    _In_    LPSTR  str
)
{
	DWORD dwHash = SEED_HASH;
	while (*str)
	{
		BYTE c = (BYTE)*str++;
		if (c >= 'a' && c <= 'z')
			c -= 'a' - 'A';

		dwHash = ((dwHash << 0x5) + dwHash) + c;
	}
	return dwHash;
}

constexpr DWORD ctime_HashStringW(
    _In_    LPCWSTR str
)
{
	DWORD dwHash = SEED_HASH;
	while (*str)
	{
		WCHAR c = *str++;
		if (c >= L'a' && c <= L'z')
			c -= L'a' - L'A';
		dwHash = ((dwHash << 0x5) + dwHash) + c;
	}
	return dwHash;
}

constexpr DWORD HASH_NTDLL      = ctime_HashStringA("Ntdll.dll");
constexpr DWORD HASH_KERNEL32   = ctime_HashStringA("Kernel32.dll");
constexpr DWORD HASH_KERNELBASE = ctime_HashStringA("Kernelbase.dll");

constexpr DWORD HASH_TPALLOCWORK   = ctime_HashStringA("TpAllocWork");
constexpr DWORD HASH_TPPOSTWORK    = ctime_HashStringA("TpPostWork");
constexpr DWORD HASH_TPRELEASEWORK = ctime_HashStringA("TpReleaseWork");

constexpr DWORD HASH_RTLCREATETIMERQUEUE  = ctime_HashStringA("RtlCreateTimerQueue");
constexpr DWORD HASH_RTLCREATETIMER       = ctime_HashStringA("RtlCreateTimer");
constexpr DWORD HASH_RTLDELETETIMERQUEUE  = ctime_HashStringA("RtlDeleteTimerQueue");
constexpr DWORD HASH_RTLDELETETIMER       = ctime_HashStringA("RtlDeleteTimer");
constexpr DWORD HASH_RTLLOOKUPFUNCTIONENTRY = ctime_HashStringA("RtlLookupFunctionEntry");
constexpr DWORD HASH_RTLCREATEHEAP			= ctime_HashStringA("RtlCreateHeap");
constexpr DWORD HASH_RTLALLOCATEHEAP      = ctime_HashStringA("RtlAllocateHeap");
constexpr DWORD HASH_RTLFREEHEAP          = ctime_HashStringA("RtlFreeHeap");
constexpr DWORD HASH_RTLDESTROYHEAP       = ctime_HashStringA("RtlDestroyHeap");
constexpr DWORD HASH_RTLUSERTHREADSTART  	= ctime_HashStringA("RtlUserThreadStart");

constexpr DWORD HASH_NTWAITFORSINGLEOBJECT    	= ctime_HashStringA("NtWaitForSingleObject");
constexpr DWORD HASH_NTFLUSHINSTRUCTIONCACHE   	= ctime_HashStringA("NtFlushInstructionCache");
constexpr DWORD HASH_NTALLOCATEVIRTUALMEMORY   	= ctime_HashStringA("NtAllocateVirtualMemory");
constexpr DWORD HASH_NTPROTECTVIRTUALMEMORY    	= ctime_HashStringA("NtProtectVirtualMemory");
constexpr DWORD HASH_NTFREEVIRTUALMEMORY       	= ctime_HashStringA("NtFreeVirtualMemory");

constexpr DWORD HASH_GETMODULEHANDLEA = ctime_HashStringA("GetModuleHandleA");
constexpr DWORD HASH_LOADLIBRARYA    = ctime_HashStringA("LoadLibraryA");
constexpr DWORD HASH_CREATEFILEW     = ctime_HashStringA("CreateFileW");
constexpr DWORD HASH_GETFILESIZE     = ctime_HashStringA("GetFileSize");
constexpr DWORD HASH_READFILE        = ctime_HashStringA("ReadFile");
constexpr DWORD HASH_CLOSEHANDLE     = ctime_HashStringA("CloseHandle");
constexpr DWORD HASH_BASETHREADINITTHUNK = ctime_HashStringA("BaseThreadInitThunk");