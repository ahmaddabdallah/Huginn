[BITS 64]

global CoffPrepareSyscall
global CoffDoSyscall

extern GetShellcodeStart
extern __INSTANCE

[SECTION .text$D]

    GetInstance:
        call GetShellcodeStart
        add rax, __INSTANCE
        ret 

    CoffPrepareSyscall:
        
        call GetInstance

        mov [rax + 0x170], rcx  ; Gadget 
        mov [rax + 0x168], edx  ; Syscall number
        ret

    CoffDoSyscall:

        call GetInstance
        mov r11, rax 

        mov r10, rcx
        mov eax, [r11 + 0x168]
        jmp [r11 + 0x170]
