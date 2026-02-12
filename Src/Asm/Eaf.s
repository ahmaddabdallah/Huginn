[BITS 64]

global ReadMemFromGadget

[SECTION .text$B]
    ReadMemFromGadget:
		mov rax, rcx
		call rdx 
		ret