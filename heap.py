#!/usr/bin/env python3

import sys
import struct
from collections import namedtuple
from elftools.elf.elffile import ELFFile


# --------------------------- Fallback (PT_LOAD) ----------------------------
def fallback_from_segments(core_elf):
    cand = []
    for seg in core_elf.iter_segments():
        if seg.header.p_type != 'PT_LOAD':
            continue
        flags = seg.header.p_flags
        PF_W = 2  # bit writable
        if flags & PF_W:
            start = seg.header.p_vaddr
            end = start + seg.header.p_memsz
            size = end - start
            offset = seg.header.p_offset   # 🔥 Offset dans le fichier core
            cand.append((start, end, size, offset))
    cand.sort(key=lambda x: x[2], reverse=True)
    return cand


def pretty_hex(x):
    return f"0x{x:016x}"




#-------------------------FUNCTION FOR STURCT_FINDER---------------------------
def find_heap(filename):
    s, e, size, off = 0, 0, 0, 0
    with open(filename, 'rb') as f:
        elf = ELFFile(f)

        print("\nFallback: scanning PT_LOAD writable segments...")
        segs = fallback_from_segments(elf)

        print("Writable PT_LOAD segments (largest first):")
        filtered = []
        for s, e, size, off in segs[:10]:
            print(f"  {pretty_hex(s)} - {pretty_hex(e)}  size={size}  offset={pretty_hex(off)}")
            # 👉 Ne garder que les segments plausibles pour le heap
            if 0x0000500000000000 <= s < 0x0000700000000000:
                filtered.append((s, e, size, off))

        if filtered:
            # on prend le plus grand segment filtré
            s, e, size, off = sorted(filtered, key=lambda x: x[2], reverse=True)[0]
            print("\nMost likely heap (heuristic: largest writable PT_LOAD in heap range):")
            print(f"  {pretty_hex(s)} - {pretty_hex(e)}  size={size}  offset={pretty_hex(off)}")
        else:
            # sinon, on retombe sur le premier par défaut
            print("\nMost likely heap (default: largest writable PT_LOAD):")
            s, e, size, off = segs[0]
            print(f"  {pretty_hex(s)} - {pretty_hex(e)}  size={size}  offset={pretty_hex(off)}")
    return s, e, size, off



# --------------------------- Main ----------------------------
def main(argv):
    if len(argv) < 2:
        print("error: enter the path of core file as argument")
        return 2

    path = argv[1]
    try:
        f = open(path, 'rb')
    except Exception as e:
        print("Cannot open core file:", e)
        return 2

    elf = ELFFile(f)

    print("\nFallback: scanning PT_LOAD writable segments...")
    segs = fallback_from_segments(elf)

    print("Writable PT_LOAD segments (largest first):")
    filtered = []
    for s, e, size, off in segs[:10]:
        print(f"  {pretty_hex(s)} - {pretty_hex(e)}  size={size}  offset={pretty_hex(off)}")
        # 👉 Ne garder que les segments plausibles pour le heap
        if 0x0000500000000000 <= s < 0x0000700000000000:
            filtered.append((s, e, size, off))

    if filtered:
        # on prend le plus grand segment filtré
        s, e, size, off = sorted(filtered, key=lambda x: x[2], reverse=True)[0]
        print("\nMost likely heap (heuristic: largest writable PT_LOAD in heap range):")
        print(f"  {pretty_hex(s)} - {pretty_hex(e)}  size={size}  offset={pretty_hex(off)}")
    else:
        # sinon, on retombe sur le premier par défaut
        print("\nMost likely heap (default: largest writable PT_LOAD):")
        s, e, size, off = segs[0]
        print(f"  {pretty_hex(s)} - {pretty_hex(e)}  size={size}  offset={pretty_hex(off)}")

    f.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
