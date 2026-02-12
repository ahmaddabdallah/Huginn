[BITS 64]

global WorkCallback

[SECTION .text$D]
    WorkCallback:
        mov rcx, [rdx + 8]     ; rcx = lpModuleName (arg pour LoadLibraryA)
        mov rax, [rdx]         ; rax = pLoadLibraryA
        jmp rax                ; tail-call vers LoadLibraryA(lpModuleName)