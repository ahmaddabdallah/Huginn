# Makefile

CC_X64     = x86_64-w64-mingw32-gcc
NASM       = nasm

SRC_DIR    = Src
ASM_DIR    = Src/Asm
INC_DIR    = Include
BIN_DIR    = Bin
TEMP_DIR   = Bin/Temp
COFF_DIR   = Coff_Example

SHLOADER_NAME	= ShLoader
LOADER_NAME = HuginnLdr
COFF_NAME   = Huginn

COFF_FLAGS  = -w -Os -s -m64 -masm=intel -fno-builtin -fno-jump-tables -Wl,-e,main

CFLAGS  = -m64 -falign-jumps=1 -falign-labels=1 -fno-builtin -w
CFLAGS += -ffunction-sections -mno-red-zone -mincoming-stack-boundary=4
CFLAGS += -fpack-struct=8 -fno-ident -Wconversion -Os 

LDFLAGS = -nostdlib -Wl,-TUtils/Linker.ld -Wl,-e,EntryPoint

INCLUDE = -I./$(INC_DIR)

.PHONY: all 

all: coff coff_loader shellcode_loader

coff:
	@ $(CC_X64) -c $(COFF_DIR)/Main.c $(COFF_FLAGS) -o $(BIN_DIR)/$(COFF_NAME).o
	@ echo "[*] COFF build with success !"


coff_loader:
	@ nasm -f win64 $(ASM_DIR)/Eaf.s 			-o $(TEMP_DIR)/Eaf.o 
	@ nasm -f win64 $(ASM_DIR)/SpoofStub.s 		-o $(TEMP_DIR)/SpoofStub.o 
	@ nasm -f win64 $(ASM_DIR)/Syscalls.s 		-o $(TEMP_DIR)/Syscalls.o 
	@ nasm -f win64 $(ASM_DIR)/Worker.s 		-o $(TEMP_DIR)/Worker.o 
	@ nasm -f win64 $(ASM_DIR)/Entry.s 			-o $(TEMP_DIR)/Entry.o
	@ nasm -f win64 $(ASM_DIR)/End.s			-o $(TEMP_DIR)/End.o 
	@ $(CC_X64) $(SRC_DIR)/*.cc $(TEMP_DIR)/*.o $(CFLAGS) $(INCLUDE) -o $(BIN_DIR)/$(LOADER_NAME).exe $(LDFLAGS)
	@ rm $(TEMP_DIR)/*.o
	@ python3 Utils/Extract.py -f $(BIN_DIR)/$(LOADER_NAME).exe -o $(BIN_DIR)/TempLdr.bin
	@ python3 Utils/Coff2Shellcode.py  -s $(BIN_DIR)/TempLdr.bin -c $(BIN_DIR)/$(COFF_NAME).o -o $(BIN_DIR)/Output.bin
	@ rm $(BIN_DIR)/TempLdr.bin $(BIN_DIR)/Huginn.o $(BIN_DIR)/$(LOADER_NAME).exe
	@ echo "[*] COFF Loader build with success !"

shellcode_loader:
	@ $(CC_X64) Utils/ShellcodeLdr.cc -o $(BIN_DIR)/$(SHLOADER_NAME).exe
	@ echo "[*] Shellcode Loader build with success !"
	@ echo "[*] All files in /$(BIN_DIR)"

clean:
	@ rm -f $(BIN_DIR)/*.exe
	@ rm -f $(BIN_DIR)/*.o
	@ rm -f $(BIN_DIR)/*.bin
	
