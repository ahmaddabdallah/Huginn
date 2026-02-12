#include <windows.h>
#include <stdio.h>

typedef void (WINAPI* Run)();

int main( int argc, char *argv[ ] )
{
    printf("[*] Shellcode path : %s\n", argv[1]);


    HANDLE hFile = CreateFileA(
        argv[1],
        GENERIC_READ,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) 
    {
        printf("Can't read shellcode ! Error : %lu\n", GetLastError());
        return EXIT_FAILURE;
	}

    DWORD   dwShellcodeSize = GetFileSize(hFile, nullptr);
    printf("[*] Shellcode size : %lu bytes\n", dwShellcodeSize);

    PVOID   pAllocatedAddress = VirtualAlloc(nullptr, dwShellcodeSize, MEM_COMMIT, PAGE_READWRITE);
    if(!pAllocatedAddress)
    {
        printf("Can't allocate memory for shellcode ! Error : %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    if(!ReadFile(
        hFile,
        pAllocatedAddress,
        dwShellcodeSize,
        nullptr,
        nullptr
    ))
    {
        printf("Can't read shellcode ! Error : %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    CloseHandle(hFile);

    DWORD dwOldProtect = 0;
    if(!VirtualProtect(
        pAllocatedAddress,
        dwShellcodeSize,
        PAGE_EXECUTE_READ,
        &dwOldProtect
    ))
    {
        printf("Can't change memory protection ! Error : %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[*] Shellcode start address : %p\n[*] Shellcode output :\n\n", pAllocatedAddress);
    reinterpret_cast<Run>(pAllocatedAddress)();
}