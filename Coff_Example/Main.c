#include <windows.h>

#include "CoffApi.h"
#include "CoffDefs.h"


void go(
    _In_    PCOFF_INFO  Info
)
{
    printf("[*] COFF executing\n");
    printf("[+] Loader  : %p - %p (%d bytes)\n", Info->MemoryStartAddress, Info->MemoryEndAddress, Info->MemorySize);
    printf("[+] COFF    : %p (%d bytes)\n", Info->CoffStartAddress, Info->CoffSize);

    //
    // 1. Load a DLL via proxy and resolve an export
    //
    HMODULE hUser32 = CoffLoadLibraryA(PROXY_TIMER, "User32.dll");
    if (!hUser32) {
        printf("[!] CoffLoadLibraryA failed\n");
        return;
    }

    void* pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    printf("[+] User32!MessageBoxA : %p\n", pMessageBoxA);

    //
    // 2. Resolve a syscall (SSN + gadget) via HalosGate
    //
    PVOID   pGadget = NULL;
    DWORD   dwSSN   = 0;

    if (!CoffResolveSyscall("NtAllocateVirtualMemory", &pGadget, &dwSSN)) {
        printf("[!] CoffResolveSyscall failed\n");
        return;
    }
    printf("[+] NtAllocateVirtualMemory : SSN = 0x%lx | Gadget = %p\n", dwSSN, pGadget);

    //
    // 3. Raw indirect syscall (no stack spoofing)
    //
    SIZE_T   stSize   = 0x1000;
    LPVOID   lpAddr   = NULL;
    NTSTATUS Status;

    CoffPrepareSyscall(pGadget, dwSSN);
    Status = CoffDoSyscall((HANDLE)-1, &lpAddr, NULL, &stSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] CoffDoSyscall        : 0x%lx -> %p\n", Status, lpAddr);

    //
    // 4. Spoofed indirect syscall (synthetic stackframe)
    //
    stSize = 0x1000;
    lpAddr = NULL;

    Status = SPOOF_SYSCALL(pGadget, dwSSN, (HANDLE)-1, &lpAddr, NULL, &stSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] SPOOF_SYSCALL        : 0x%lx -> %p\n", Status, lpAddr);

    //
    // 5. Spoofed API call (synthetic stackframe, no syscall)
    //
    void* pLoadLibraryA = &LoadLibraryA;
    HMODULE hChakra = (HMODULE)SPOOF_API(pLoadLibraryA, "chakra.dll");
    printf("[+] SPOOF_API            : chakra.dll -> %p\n", hChakra);

    //
    // 6. Heap allocation via COFF loader (auto-cleaned after execution)
    //
    PVOID pBuffer = CoffAlloc(256);
    printf("[+] CoffAlloc            : %p\n", pBuffer);
    CoffFree(pBuffer);

    printf("[*] COFF done\n");
}
