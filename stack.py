#!/usr/bin/env python3

import sys
from elftools.elf.elffile import ELFFile

def pretty_hex(x):
    return f"0x{x:016x}"


#-------------------------FUNCTION FOR STURCT_FINDER---------------------------

def find_stack(core_file):
    s, e, size, off = 0, 0, 0, 0
    with open(core_file, 'rb') as f:
        elf = ELFFile(f)

        last_rw = None  # pour stocker le dernier segment RW trouvé

        print("\nScanning PT_LOAD writable segments...")
        for seg in elf.iter_segments():
            if seg.header.p_type != 'PT_LOAD':
                continue
            flags = seg.header.p_flags
            PF_W = 2  # writable bit
            if flags & PF_W:
                start = seg.header.p_vaddr
                end = start + seg.header.p_memsz
                size = end - start
                offset = seg.header.p_offset
                print(f"  RW segment -> start={pretty_hex(start)}, end={pretty_hex(end)}, size={size}, offset={pretty_hex(offset)}")
                last_rw = (start, end, size, offset)

        if last_rw:
            s, e, size, off = last_rw
            print("\n Last writable PT_LOAD segment (most likely stack):")
            print(f"  start={pretty_hex(s)}  end={pretty_hex(e)}  size={size}  offset={pretty_hex(off)}")
    return s, e, size, off




#------------------ MAIN ---------------------------------------
def main(argv):
    if len(argv) < 2:
        print("Usage: ./stack.py <core-file>")
        return 2

    path = argv[1]
    try:
        f = open(path, 'rb')
    except Exception as e:
        print("Cannot open core file:", e)
        return 2

    elf = ELFFile(f)

    last_rw = None  # pour stocker le dernier segment RW trouvé

    print("\nScanning PT_LOAD writable segments...")
    for seg in elf.iter_segments():
        if seg.header.p_type != 'PT_LOAD':
            continue
        flags = seg.header.p_flags
        PF_W = 2  # writable bit
        if flags & PF_W:
            start = seg.header.p_vaddr
            end = start + seg.header.p_memsz
            size = end - start
            offset = seg.header.p_offset
            print(f"  RW segment -> start={pretty_hex(start)}, end={pretty_hex(end)}, size={size}, offset={pretty_hex(offset)}")
            last_rw = (start, end, size, offset)

    if last_rw:
        s, e, size, off = last_rw
        print("\n Last writable PT_LOAD segment (most likely stack):")
        print(f"  start={pretty_hex(s)}  end={pretty_hex(e)}  size={size}  offset={pretty_hex(off)}")


    f.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
