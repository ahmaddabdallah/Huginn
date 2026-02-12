#include <windows.h>

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPSTR);
DECLSPEC_IMPORT void __cdecl MSVCRT$printf(...);

#define LoadLibraryA        KERNEL32$LoadLibraryA
#define GetProcAddress      KERNEL32$GetProcAddress
#define printf              MSVCRT$printf