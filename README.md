# Huginn Project


![Huginn](/Img/Huginn.jpg)

Huginn is a position-independent COFF loader designed for in-memory execution with built-in stack spoofing, indirect syscalls and automatic heap cleanup to prevent memory leaks.

## How it works

The COFF object file (`.o`) is appended to the loader shellcode and loaded entirely in memory — no file is dropped on disk.

### Build pipeline

```
Main.c ──(mingw -c)──► Huginn.o

Src/*.cc + Asm/*.s ──(mingw -nostdlib + linker script)──► HuginnLdr.exe

HuginnLdr.exe ──(Extract.py)──► CoffeLoader.bin  (raw .text shellcode)

CoffeLoader.bin + Huginn.o ──(Coff2Shellcode.py)──► Output.bin
```

The linker script (`Utils/Linker.ld`) orders sections via `.text$A` through `.text$Z` to guarantee execution flow without a CRT.

### Loader execution flow

1. **PreMain** — Resolves `ntdll`, `kernel32`, `kernelbase` by PEB walk using compile-time hashes. Resolves all required WinAPI and Nt functions. Sets up stack spoofing parameters (`BaseThreadInitThunk`, `RtlUserThreadStart`, `jmp rbx` gadget) and computes their stack frame sizes via unwind info parsing.

2. **ShellcodeEntry** — Creates a private heap (`RtlCreateHeap`) for the COFF loader context, then executes the loading pipeline:
   - `InitializeCoffContext` — Validates the COFF header (x64 machine type, section bounds, symbol table). Allocates an IAT table via `NtAllocateVirtualMemory`.
   - `AllocateMemorySection` — Allocates each COFF section in its own virtual memory region and copies raw data.
   - `LoadAndResolveSymbols` — Iterates the COFF symbol table. Resolves `__imp_Coff*` symbols to internal loader functions, `__imp_DLL$Function` symbols by loading the DLL and resolving exports via hash (with EAF bypass), and locates the `go` entry point.
   - `ApplyRelocations` — Processes AMD64 relocations (`ADDR64`, `ADDR32NB`, `REL32`, `REL32_4`) using a GOT for imported symbols.
   - `ApplyMemoryProtection` — Sets proper page protections (RX, RO, RW) per section characteristics. IAT is set to read-only.
   - `ExecuteEntryPoint` — Flushes instruction cache and calls the `go` function.

3. **Cleanup** — All section memory, symbol tables, IAT, and COFF content are freed. The COFF's dedicated heap is destroyed to prevent memory leaks.

### Evasion features

- **Indirect syscalls** via HalosGate (SSN resolution) + `syscall` gadget in `ntdll`
- **Stack spoofing** through synthetic frames (`BaseThreadInitThunk` → `RtlUserThreadStart`) with `jmp rbx` gadget
- **EAF bypass** using `ReadMemFromGadget` to read export tables without triggering hardware breakpoints
- **No CRT / no imports** — Position-independent shellcode with all APIs resolved at runtime by hash
- **Proxy calls** — `LoadLibraryA` proxied through threadpool or timer callbacks

## How to use

Write your code in `Coff_Example/Main.c`. The entry point must be a function named `go` that takes a `PCOFF_INFO` parameter:

```C
void go(PCOFF_INFO Info) {
    // your code here
}
```

### COFF_INFO

The `go` function receives a `PCOFF_INFO` structure providing metadata about the loader and the COFF in memory:

```C
typedef struct _COFF_INFO {
    void*   MemoryStartAddress;   // Start of the loader shellcode in memory
    void*   MemoryEndAddress;     // End of the loader shellcode in memory
    void*   CoffStartAddress;     // Start of the COFF object file in memory
    long    MemorySize;           // Total size (loader + COFF)
    long    CoffSize;             // Size of the COFF object file
} COFF_INFO, *PCOFF_INFO;
```

This allows the COFF to know its own memory layout — useful for self-cleanup, memory scanning, or passing context to sub-components.

### Importing DLL functions

Since the COFF is compiled without linking (`-c`), all external functions must be declared using the `DECLSPEC_IMPORT` pattern with the `DLL$Function` naming convention in `Coff_Example/CoffDefs.h`:

```C
// Declaration
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPSTR);
DECLSPEC_IMPORT void __cdecl MSVCRT$printf(...);

// Macro alias for convenience
#define LoadLibraryA   KERNEL32$LoadLibraryA
#define printf         MSVCRT$printf
```

The loader resolves `__imp_KERNEL32$LoadLibraryA` at runtime by loading the DLL and resolving the export by hash.

> **Warning:** If a function is used without being declared this way, the `-w` flag will suppress the warning and the symbol will become an unresolved `__imp_` import, causing a silent load failure.

### Building

```bash
make coff            # Compile the COFF object file
make coff_loader     # Build the loader + extract shellcode + merge with COFF
make all             # Both
```

The final output is `Bin/Output.bin` — the self-contained shellcode ready for execution.

### Verifying imports

Use `Utils/DumpCoff.py` to inspect the COFF symbols before loading. Functions that don't start with `__imp_` (except `go`) are highlighted in red as potential issues:

```bash
python3 Utils/DumpCoff.py -f Bin/Huginn.o
```

## CoffAPI

### Module Loading

```C++
typedef enum _LOADLIB_METHOD {
    THREAD_POOL,
    PROXY_TIMER,
    NONE
} LOADLIB_METHOD;

HMODULE CoffLoadLibraryA(
    _In_    LOADLIB_METHOD  Method,
    _In_    LPSTR  lpModuleName
);
```

Load a module via `KERNEL32!LoadLibraryA` using a proxy method to avoid direct calls.

| Method | Description |
|--------|-------------|
| `THREAD_POOL` | Proxied through threadpool callback |
| `PROXY_TIMER` | Proxied through timer callback |
| `NONE` | Called with synthetic stackframe |

---

### Syscall Resolution

```C++
bool CoffResolveSyscall(
    _In_    LPSTR   lpFunctionName,
    _Inout_ PVOID   *ppGadget,
    _Inout_ PDWORD  pdwSyscall
);
```

Resolve the syscall number (SSN) and a `syscall` instruction gadget for a given `ntdll` function using HalosGate.

---

### Raw Indirect Syscall

```C++
VOID CoffPrepareSyscall(
    _In_    PVOID   pGadget,
    _In_    DWORD   dwSyscall
);

NTSTATUS CoffDoSyscall(...);
```

Execute an indirect syscall without stack spoofing. Call `CoffPrepareSyscall` to set the gadget and SSN, then invoke `CoffDoSyscall` with the syscall arguments.

> **Warning:** `CoffDoSyscall` does not use any spoofing mechanism. The stackframe is left unwound and may be flagged by stack-walking detections.

---

### Spoofed Syscall

```C++
SPOOF_SYSCALL(Fn, Ssn, ...);
```

Perform an indirect syscall through a synthetic stackframe. Combines syscall resolution and stack spoofing in a single macro.

| Parameter | Description |
|-----------|-------------|
| `Fn` | Pointer to the target function |
| `Ssn` | Syscall number |
| `...` | Syscall arguments |

---

### Spoofed API Call

```C++
SPOOF_API(Fn, ...);
```

Call any function through a synthetic stackframe. Equivalent to `SPOOF_SYSCALL` with SSN set to `0`.

| Parameter | Description |
|-----------|-------------|
| `Fn` | Pointer to the target function |
| `...` | Function arguments |

---

### Memory Management

```C++
PVOID CoffAlloc(
    _In_   SIZE_T  stSize
);

PVOID CoffFree(
    _In_   PVOID   pAddress
);
```

Allocate and free memory from a dedicated heap created by the COFF Loader. The heap is destroyed after COFF execution to prevent any memory leak.

## Mentions

- COFF development reference: [Sektor7 - MalwareDev - v1](https://institute.sektor7.net/rto-maldev-adv1)
- Debug, refactoring and README: [Claude](https://claude.ai)
- README image: [Grok](https://x.com/i/grok)
