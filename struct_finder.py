#!/usr/bin/env python3
import json, sys, os
import struct as struct_mod
from heap import find_heap, find_mmap_heap
from stack import find_stack
# ---------------- CONFIG ----------------
CORE_FILE = "core.100"  # path to core file
START_ADDR = 0x000055cc0a022000#0x000055f1a1ef5000#0x00005644e8619000 # 0x5644e861a320
END_ADDR   = START_ADDR + 0x000000000283e000#0x0000000000413000#0x0000000000097000
SEGMENT_VADDR = START_ADDR#0x00005644e8619000#0x5644e8619000 # 0x560d0fb60000
SEGMENT_OFFSET = 0x0000000000003430#0x0000000000003430 #0x33c0
ALIGN = 8  # pointer alignment
MAX_RESULTS = None
STACK_START = 0x7f0000000000
STACK_END = 0x7fffffffffff
MMAP_HEAP_START = 0x7f0000000000
MMAP_HEAP_END = 0x7fffffffffff
# ----------------------------------------


#-----------------------------------------
def read_memory(core_file, start_addr, end_addr, seg_offset, seg_vaddr):
    """Read memory bytes from core file for a virtual address range"""
    file_offset_start = seg_offset + (start_addr - seg_vaddr)
    size = end_addr - start_addr
    with open(core_file, "rb") as f:
        f.seek(file_offset_start)
        data = f.read(size)
    return data, file_offset_start


def find_valid_pointers(mem_blob, base_addr, align=8):
    """Scan memory for pointers pointing inside the same region"""
    valid_ptrs = set()
    size = len(mem_blob)
    for i in range(0, size - 8 + 1, align):
        val = struct_mod.unpack_from("<Q", mem_blob, i)[0]
        if (START_ADDR <= val < END_ADDR) or (val==0) or (STACK_START < val < STACK_END) or (MMAP_HEAP_START < val < MMAP_HEAP_END):
            valid_ptrs.add(base_addr + i)  # store location of pointer itself
    return valid_ptrs


def detect_structs(mem_blob, base_addr, structs, valid_ptr_locs):
    """Detect struct instances in memory using pointer validation"""
    heap_size = len(mem_blob)
    detected = {}
    for struct in structs:
        name = struct['name']
        if "array" in name:
            continue
        print("\n" + "=" * 50)
        print(f"🔹 TRYING FOR STRUCT: {name}")
        print("=" * 50)        
        size = struct['size']
        pointer_offsets = [m['data_member_location'] for m in struct['members']
                           if m['type'] and '*' in m['type'] and m['data_member_location'] is not None]
        if not pointer_offsets:
            continue

        struct_matches = []
        for offset in range(0, heap_size - size + 1,8):
            addr = base_addr + offset
            #if int.from_bytes(mem_blob[offset: offset + struct["size"]], byteorder='little') == 0:
            #    continue
            if all((addr + p_off) in valid_ptr_locs for p_off in pointer_offsets):
                ascii_ok = True
                print(f"Struct candidate at 0x{addr:X}")
                for p_off in pointer_offsets:
                    ptr_addr = addr + p_off
                    ptr_val = struct_mod.unpack_from("<Q", mem_blob, offset + p_off)[0]
                    print(f"  Pointer at offset {p_off}: 0x{ptr_val:X}")
                for m in struct['members']:
                        t = m['type']
                        if t and '[' in t and m['data_member_location'] is not None:
                            base = t.split('[')[0].strip()
                            # print(base)  # extract type before the [
                            if base == 'char (size=1)':  # only accept real char array
                                    # print("we are checking for char")
                                    m_off = m['data_member_location']
                                    m_len = int(t.split('[')[1].split(']')[0])
                                    member_bytes = mem_blob[offset + m_off : offset + m_off + m_len]
                                    # print("expected length is", m_len - 1)
                                    string_val = member_bytes.split(b'\x00')[0].decode('ascii', errors='ignore')
                                    print(f"  Member {m['name']} at offset {m_off}: '{string_val}'")
                                    if (not all(32 <= b < 127  for b in member_bytes[:-1])) or member_bytes[-1] != 0:
                                        #if name == "Struct15_t":
                                        #    print("not all ascii")
                                        ascii_ok = False
                                        break
                                    #elif member_bytes[-1] != 0 :
                                    #    if name == "Struct15_t":
                                    #        print("last character is not 0")
                                    # else: print("ASCII OK FOR STRING,", m)

                if ascii_ok:
                    enums_ok = True
                    for m in struct['members']:
                        t = m['type']
                        if t and ('enum' in t or 'enum' in t.lower()) and m['data_member_location'] is not None:
                            enum_off = m['data_member_location']
                            enum_size = m.get('size', 4)  # default to 4 bytes
                            enum_bytes = mem_blob[offset + enum_off : offset + enum_off + enum_size]
                            if len(enum_bytes) < enum_size:
                                print("enum doesnt match, enumbytes len, ", enum_bytes, " while enum size ", enum_size)
                                enums_ok = False
                                break
                            enum_val = int.from_bytes(enum_bytes, byteorder='little', signed=False)
                            if not (0 <= enum_val <= 3):
                                enums_ok = False
                                if name == "Struct15_t":
                                    print("enum doesnt match,", enum_val)
                                break

                    if enums_ok:
                        struct_matches.append(addr)
                        if struct_matches:
                            detected[name] = struct_matches
                            #if name == 'array_entry':
                            #    continue
                            print(f"Detected {len(struct_matches)} instance(s) of {name}:")
                            #for a in struct_matches:
                            #    print(f"  0x{a:016x}")
    return detected


#---------------------- HELPER FUNCTION----------------------------------------
def update_globals(core_file):
    global START_ADDR, END_ADDR, SEGMENT_OFFSET, SEGMENT_VADDR, STACK_START, STACK_END, MMAP_HEAP_START, MMAP_HEAP_END
    start, end, size, offset = find_heap(core_file)
    START_ADDR = start     
    END_ADDR = end 
    SEGMENT_OFFSET = offset 
    SEGMENT_VADDR = START_ADDR
    start, end, *_ = find_stack(core_file)
    STACK_START = start
    STACK_END = end
    start, end, *_ = find_mmap_heap(core_file)
    MMAP_HEAP_START = start
    MMAP_HEAP_END = end
    return 0

#-------------------------------------------------------------------------------
def main():
    if len(sys.argv) != 3:
        print("Usage: detect_structs.py <structs.json> <dump_file>")
        return 1

    json_path = sys.argv[1]
    if not os.path.isfile(json_path):
        print("Structs JSON not found:", json_path)
        return 1

    CORE_FILE = sys.argv[2]
    if not os.path.isfile(json_path):
        print("Dump file not found:", CORE_FILE)
        return 1
    
    # load structs JSON (sorted by pointer count descending)
    with open(json_path, 'r') as f:
        structs = json.load(f)

    # try to find the heap position with heuristics
    update_globals(CORE_FILE)
    
    # read memory
    mem_blob, _ = read_memory(CORE_FILE, START_ADDR, END_ADDR, SEGMENT_OFFSET, SEGMENT_VADDR)
    print(f"Read {len(mem_blob)} bytes from memory 0x{START_ADDR:x}-0x{END_ADDR:x}")

    # detect valid pointer locations
    valid_ptr_locs = find_valid_pointers(mem_blob, START_ADDR)
    print(f"Found {len(valid_ptr_locs)} valid pointers in memory region")

    # detect structs
    detected = detect_structs(mem_blob, START_ADDR, structs, valid_ptr_locs)
    total = sum(len(v) for v in detected.values())
    print(f"\n✅ Total detections: {total}")
    output_file = "candidates.json"
    with open(output_file, "w") as f:
        json.dump(detected, f, indent=4)

    print(f"Wrote detected candidates to {output_file}")

if __name__ == "__main__":
    main()
