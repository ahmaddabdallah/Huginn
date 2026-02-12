#include <windows.h>

#include "Prototypes.h"

#define SEED_HASH   0x1337

#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )

#define U_PTR(x)            (reinterpret_cast<UINT_PTR>(x))
#define C_PBYTE(x)          (reinterpret_cast<PBYTE>(x))

#define	EAF_READ_DW32(x)	((DWORD)(UINT_PTR)ReadMemFromGadget(x, pGadgetRead))
#define	EAF_READ_W(x)		((WORD)(UINT_PTR)ReadMemFromGadget(x, pGadgetRead))

#define INSTANCE_ADDRESS    reinterpret_cast<UINT_PTR>(GetShellcodeStart() + (UINT_PTR)&__INSTANCE)

#define SHELLCODE_SIZE      (reinterpret_cast<UINT_PTR>(GetShellcodeEnd() - GetShellcodeStart()))
#define COFF_SIZE           (*reinterpret_cast<PDWORD>(GetShellcodeEnd()))
#define TOTAL_SIZE          (SHELLCODE_SIZE + COFF_SIZE + sizeof(DWORD))

#define GLOBAL_INSTANCE     reinterpret_cast<PINSTANCE>(INSTANCE_ADDRESS)

#define RESOLVE_FUNCTION(Mod, Hash)   ResolveProcedureAddressWithHash(Inst.EafGadget, Inst.Module.Mod, Hash);

#define DRAUGR_API_X(Name) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_A(Name, a) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_B(Name, a, b) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_C(Name, a, b, c) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_D(Name, a, b, c, d) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_E(Name, a, b, c, d, e) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_F(Name, a, b, c, d, e, f) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_G(Name, a, b, c, d, e, f, g) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_H(Name, a, b, c, d, e, f, g, h) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), NULL, NULL, NULL, NULL)

#define DRAUGR_API_I(Name, a, b, c, d, e, f, g, h, i) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), NULL, NULL, NULL)

#define DRAUGR_API_J(Name, a, b, c, d, e, f, g, h, i, j) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), NULL, NULL)

#define DRAUGR_API_K(Name, a, b, c, d, e, f, g, h, i, j, k) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), NULL)

#define DRAUGR_API_L(Name, a, b, c, d, e, f, g, h, i, j, k, l) \
    DraugrCall(GLOBAL_INSTANCE, GLOBAL_INSTANCE->WinApi.Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), (PVOID)(l))

#define DRAUGR_API_EXPAND(x) x
#define DRAUGR_API_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, NAME, ...) NAME

#define DRAUGR_API(Name, ...) \
    DRAUGR_API_EXPAND(DRAUGR_API_GET_MACRO(__VA_ARGS__, \
        DRAUGR_API_L, DRAUGR_API_K, DRAUGR_API_J, DRAUGR_API_I, \
        DRAUGR_API_H, DRAUGR_API_G, DRAUGR_API_F, DRAUGR_API_E, \
        DRAUGR_API_D, DRAUGR_API_C, DRAUGR_API_B, DRAUGR_API_A, \
        DRAUGR_API_X)(Name, __VA_ARGS__))