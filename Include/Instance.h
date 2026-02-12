#pragma once

typedef struct _INSTANCE 
{
    struct {
        void*   Ntdll;
        void*   Kernelbase;
        void*   Kernel32;
    } Module;

    struct {
        void*   TpAllocWork;
        void*   TpPostWork;
        void*   TpReleaseWork;

        void*   RtlCreateTimerQueue;
        void*   RtlCreateTimer;
        void*   RtlDeleteTimerQueue;
        void*   RtlDeleteTimer;
        void*   RtlLookupFunctionEntry;
        void*   RtlCreateHeap;
        void*   RtlAllocateHeap;
        void*   RtlFreeHeap;
        void*   RtlDestroyHeap;

        void*   NtWaitForSingleObject;
        void*   NtFlushInstructionCache;
        void*   NtAllocateVirtualMemory;
        void*   NtProtectVirtualMemory;
        void*   NtFreeVirtualMemory;

        void*   LoadLibraryA;

        void*   CreateFileW;
        void*   GetFileSize;
        void*   ReadFile;
        void*   CloseHandle;
    } WinApi;

    struct {
        void*       Fixup;             
        void*       OG_retaddr;        
        void*       Rbx;               
        void*       Rdi;               
        void*       FirstFrameSize;           
        void*       FirstFrame;      
        void*       GadgetFrameSize;         
        void*       SecondFrameSize;           
        void*       SecondFrame;     
        void*       Ssn;               
        void*       Gadget;        
        void*       Rsi;               
        void*       R12;               
        void*       R13;               
        void*       R14;               
        void*       R15;               
    } Param;

    struct {
        void*       StartAddress;
        void*       EndAddress;
        int         Size;
    } MemoryInfo;

    struct {
        void*   Heap;               // 352  - 0x160

        /*
            IF THIS FUNCTION OFFSET CHANGE, NEED TO EDIT Syscalls.s !!!!!
        */
        long    SyscallNumber;      // 360  - 0x168
        void*   SyscallGadget;      // 368  - 0x170
    } CoffInfo; // 352

    void*   EafGadget;
} INSTANCE, *PINSTANCE;

typedef struct _COFF_INFO {
    void*   MemoryStartAddress;
    void*   MemoryEndAddress;
    void*   CoffStartAddress;
    long    MemorySize;
    long    CoffSize;
} COFF_INFO, *PCOFF_INFO;