import argparse
import struct

IMAGE_SYM_CLASS_EXTERNAL = 2

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Dump COFF object file symbols.')
    parser.add_argument('-f', required=True, help='Path to .o file', type=str)
    args = parser.parse_args()

    with open(args.f, 'rb') as f:
        data = f.read()

    machine, num_sections, _, sym_offset, num_symbols, _, _ = struct.unpack_from(
        '<HHIIIHH', data, 0
    )

    str_table_offset = sym_offset + (num_symbols * 18)

    print(f"Size : {len(data)} bytes")
    print(f"Machine: 0x{machine:04X}")
    print(f"Sections: {num_sections}")
    print(f"Symbols: {num_symbols}\n")
    print(f"{'Index':<8}{'Name':<40}{'Value':<12}{'Section':<10}{'Class'}")
    print("-" * 80)

    i = 0
    while i < num_symbols:
        entry_offset = sym_offset + (i * 18)
        name_bytes = data[entry_offset:entry_offset + 8]
        value, section, _, storage_class, aux_count = struct.unpack_from(
            '<IhHBB', data, entry_offset + 8
        )

        if name_bytes[:4] == b'\x00\x00\x00\x00':
            str_off = struct.unpack_from('<I', name_bytes, 4)[0]
            end = data.index(b'\x00', str_table_offset + str_off)
            name = data[str_table_offset + str_off:end].decode('ascii', errors='replace')
        else:
            name = name_bytes.rstrip(b'\x00').decode('ascii', errors='replace')

        label = ""
        if storage_class == IMAGE_SYM_CLASS_EXTERNAL and section > 0:
            label = "EXPORT"
        elif storage_class == IMAGE_SYM_CLASS_EXTERNAL and section == 0 and value == 0:
            label = "IMPORT"

        if label:
            RED = "\033[91m"
            RESET = "\033[0m"
            line = f"{i:<8}{name:<40}{value:<12}{section:<10}{label}"
            if not name.startswith("__imp_") and name != "go":
                line = f"{RED}{line}{RESET}"
            print(line)

        i += 1 + aux_count
