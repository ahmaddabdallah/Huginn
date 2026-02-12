#include <windows.h>

typedef enum _LOADLIB_METHOD {
    THREAD_POOL,
    PROXY_TIMER,
    NONE
} LOADLIB_METHOD;

typedef struct _COFF_INFO {
    void*   MemoryStartAddress;
    void*   MemoryEndAddress;
    void*   CoffStartAddress;
    long    MemorySize;
    long    CoffSize;
} COFF_INFO, *PCOFF_INFO;

DECLSPEC_IMPORT HMODULE WINAPI CoffLoadLibraryA(
    _In_    LOADLIB_METHOD  Method,
    _In_    LPSTR  lpModuleName
);

DECLSPEC_IMPORT  BOOL WINAPI    CoffResolveSyscall(
    _In_    LPSTR  lpFunctionName,
    _Inout_ PVOID   *ppGadget,
    _Inout_ PDWORD  pdwSyscall
);

DECLSPEC_IMPORT VOID WINAPI CoffPrepareSyscall(
    _In_    PVOID   pGadget,
    _In_    DWORD   dwSyscall
);

DECLSPEC_IMPORT NTSTATUS WINAPI CoffDoSyscall(...);

DECLSPEC_IMPORT UINT_PTR	WINAPI CoffSpoofCall(
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


DECLSPEC_IMPORT PVOID   WINAPI  CoffAlloc(
	_In_	SIZE_T	stSize
);

DECLSPEC_IMPORT PVOID	WINAPI  CoffFree(
	_In_	PVOID	pAddress
);

#define _SPOOF_X(Fn, Ssn) \
    CoffSpoofCall(Fn, Ssn, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define _SPOOF_A(Fn, Ssn, a) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define _SPOOF_B(Fn, Ssn, a, b) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define _SPOOF_C(Fn, Ssn, a, b, c) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), (PVOID)(c), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define _SPOOF_D(Fn, Ssn, a, b, c, d) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define _SPOOF_E(Fn, Ssn, a, b, c, d, e) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define _SPOOF_F(Fn, Ssn, a, b, c, d, e, f) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), NULL, NULL, NULL, NULL, NULL, NULL)

#define _SPOOF_G(Fn, Ssn, a, b, c, d, e, f, g) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), NULL, NULL, NULL, NULL, NULL)

#define _SPOOF_H(Fn, Ssn, a, b, c, d, e, f, g, h) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), NULL, NULL, NULL, NULL)

#define _SPOOF_I(Fn, Ssn, a, b, c, d, e, f, g, h, i) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), NULL, NULL, NULL)

#define _SPOOF_J(Fn, Ssn, a, b, c, d, e, f, g, h, i, j) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), NULL, NULL)

#define _SPOOF_K(Fn, Ssn, a, b, c, d, e, f, g, h, i, j, k) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), NULL)

#define _SPOOF_L(Fn, Ssn, a, b, c, d, e, f, g, h, i, j, k, l) \
    CoffSpoofCall(Fn, Ssn, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), (PVOID)(l))

#define _SPOOF_EXPAND(x) x
#define _SPOOF_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, NAME, ...) NAME

#define SPOOF_SYSCALL(Fn, Ssn, ...) \
    _SPOOF_EXPAND(_SPOOF_GET_MACRO(__VA_ARGS__, \
        _SPOOF_L, _SPOOF_K, _SPOOF_J, _SPOOF_I, \
        _SPOOF_H, _SPOOF_G, _SPOOF_F, _SPOOF_E, \
        _SPOOF_D, _SPOOF_C, _SPOOF_B, _SPOOF_A, \
        _SPOOF_X)(Fn, Ssn, __VA_ARGS__))

#define SPOOF_API(Fn, ...) \
    _SPOOF_EXPAND(_SPOOF_GET_MACRO(__VA_ARGS__, \
        _SPOOF_L, _SPOOF_K, _SPOOF_J, _SPOOF_I, \
        _SPOOF_H, _SPOOF_G, _SPOOF_F, _SPOOF_E, \
        _SPOOF_D, _SPOOF_C, _SPOOF_B, _SPOOF_A, \
        _SPOOF_X)(Fn, 0, __VA_ARGS__))