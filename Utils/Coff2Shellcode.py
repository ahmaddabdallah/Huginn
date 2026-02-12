import argparse
import struct

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser( description = 'Add COF to shellcode. ' )
        parser.add_argument( '-s', required = True, help = 'Path to the shellcode', type=str, dest = 'shellcode' )
        parser.add_argument( '-c', required = True, help = 'Path to coff file', type = str, dest = 'coff' )
        parser.add_argument( '-o', required = True, help = 'Path to store the output raw binary', type = str, dest = 'output' )
        options = parser.parse_args()

        hFile = open(options.shellcode, "rb")
        shellcode = hFile.read()
        hFile.close()

        hFile = open(options.coff, "rb")
        coff = hFile.read()
        hFile.close()

        shellcode_content = shellcode + struct.pack('<I', len(coff)) + coff
        print(f"[*] Shellcode size : {len(shellcode_content)} bytes")

        hFile = open(options.output, "wb")
        hFile.write(shellcode_content)
        hFile.close()
    except Exception as e:
        print( '[!] error: {}'.format( e ) );

