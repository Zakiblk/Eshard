#!/usr/bin/env python3
"""
dump_dwarf_structs.py

Usage:
    python3 dump_dwarf_structs.py <path-to-elf>

Requirements:
    pip install pyelftools
"""

import sys
from collections import OrderedDict
from elftools.elf.elffile import ELFFile
import json




# --- helpers to read attributes safely ------------------------------------
def attr_str(die, name):
    a = die.attributes.get(name)
    if not a:
        return None
    v = a.value
    # string values are sometimes bytes
    if isinstance(v, bytes):
        try:
            return v.decode('utf-8', errors='replace')
        except Exception:
            return str(v)
    return v

def attr_int(die, name):
    a = die.attributes.get(name)
    if not a:
        return None
    return a.value

# --- load all DIEs into a map: offset -> DIE --------------------------------
def build_die_map(dwarfinfo):
    die_map = {}
    cu_map = {}  # die offset -> CU (for lookups if needed)
    for cu in dwarfinfo.iter_CUs():
        top = cu.get_top_DIE()
        for die in cu.iter_DIEs():
            die_map[die.offset] = die
            cu_map[die.offset] = cu
    return die_map, cu_map

# --- resolve a type DIE into a human readable representation -----------------
def resolve_type(die_map, type_offset, _seen=None):
    """
    Return a textual representation for a type referenced by `type_offset`.
    `die_map` maps offsets to DIE objects.
    This is recursive, with protection against cycles.
    """
    if type_offset is None:
        return 'void'

    if _seen is None:
        _seen = set()
    if type_offset in _seen:
        return '<recursive>'
    _seen.add(type_offset)

    tdie = die_map.get(type_offset)
    if tdie is None:
        return f'<unknown-type@0x{type_offset:x}>'

    tag = tdie.tag

    # Base types and typedefs
    if tag == 'DW_TAG_base_type':
        name = attr_str(tdie, 'DW_AT_name') or '<base>'
        byte_size = attr_int(tdie, 'DW_AT_byte_size')
        if byte_size is not None:
            return f"{name} (size={byte_size})"
        return name

    if tag == 'DW_TAG_typedef':
        name = attr_str(tdie, 'DW_AT_name') or '<typedef>'
        target = attr_int(tdie, 'DW_AT_type')
        if target:
            return f"typedef {name} -> {resolve_type(die_map, target, _seen)}"
        return f"typedef {name}"

    if tag == 'DW_TAG_pointer_type':
        # pointer may have DW_AT_type pointing to pointed-to type
        target = attr_int(tdie, 'DW_AT_type')
        target_repr = resolve_type(die_map, target, _seen) if target else 'void'
        bsize = attr_int(tdie, 'DW_AT_byte_size')
        if bsize:
            return f"{target_repr}* (ptr_size={bsize})"
        return f"{target_repr}*"

    if tag == 'DW_TAG_const_type' or tag == 'DW_TAG_volatile_type' or tag == 'DW_TAG_restrict_type':
        target = attr_int(tdie, 'DW_AT_type')
        prefix = tag.replace('DW_TAG_', '').replace('_type', '')
        return f"{prefix} {resolve_type(die_map, target, _seen)}"

    if tag == 'DW_TAG_array_type':
        target = attr_int(tdie, 'DW_AT_type')
        elem = resolve_type(die_map, target, _seen) if target else '<elem?>'
        bounds = []
        for ch in tdie.iter_children():
            if ch.tag == 'DW_TAG_subrange_type':
                ub = attr_int(ch, 'DW_AT_upper_bound')
                if ub is not None:
                    ub += 1  # fix off-by-one for arrays
                bounds.append(str(ub) if ub is not None else '?')
        return f"{elem}[{']['.join(bounds)}]" if bounds else f"{elem}[]"

    if tag == 'DW_TAG_structure_type' or tag == 'DW_TAG_union_type' or tag == 'DW_TAG_class_type':
        name = attr_str(tdie, 'DW_AT_name') or '<anon>'
        bsize = attr_int(tdie, 'DW_AT_byte_size')
        kind = 'struct' if 'structure' in tag else ('union' if 'union' in tag else 'class')
        if bsize:
            return f"{kind} {name} (size={bsize})"
        return f"{kind} {name}"

    # enumerations
    if tag == 'DW_TAG_enumeration_type':
        name = attr_str(tdie, 'DW_AT_name') or '<enum>'
        return f"enum {name}"

    # fallback
    tname = attr_str(tdie, 'DW_AT_name')
    return tname or f"<{tag}>"

# --- main scan to find struct DIEs and collect members -----------------------
def dump_structs(dwarfinfo,struct_list):
    die_map, cu_map = build_die_map(dwarfinfo)
    structs = collect_structs(die_map)  # or core file
    # collect structure DIEs
    structs = OrderedDict()  # offset -> (die, info)
    for off, die in die_map.items():
        if die.tag == 'DW_TAG_structure_type':
            # skip forward-declaration-only structs without content? still include
            structs[off] = die

    # print nicely
    results = []
    for off, sdie in structs.items():
        struct_name = attr_str(sdie, 'DW_AT_name') or f"<anon@0x{off:x}>"
        # Try the struct's own name first
        struct_name = attr_str(sdie, 'DW_AT_name')

        # If no name, try to find a typedef that references this struct
        if not struct_name:
            typedef_name = None
            for die in die_map.values():
                if die.tag == 'DW_TAG_typedef':
                    tref = attr_int(die, 'DW_AT_type')
                    if tref == off:
                        typedef_name = attr_str(die, 'DW_AT_name')
                        if typedef_name:
                            break
            struct_name = typedef_name or f"<anon@0x{off:x}>"

        struct_size = attr_int(sdie, 'DW_AT_byte_size')
        members = []
        # children that are DW_TAG_member
        for child in sdie.iter_children():
            if child.tag != 'DW_TAG_member':
                continue
            mname = attr_str(child, 'DW_AT_name') or '<anon_member>'
            # type reference: DW_AT_type -> offset (an int)
            typeref = attr_int(child, 'DW_AT_type')
            type_repr = resolve_type(die_map, typeref)
            # data member location (offset in bytes) -> can be const or expr; pyelftools gives integer for constants
            data_loc = child.attributes.get('DW_AT_data_member_location')
            if data_loc is None:
                data_loc_val = None
            else:
                data_loc_val = data_loc.value
            # optionally size of member if type is base type with size or if array element sizes known
            member_size = None
            # attempt to determine byte size from the type DIE (follow typedef/pointer resolution to base)
            try:
                # try to get final DIE and its byte size if present
                if typeref:
                    final = die_map.get(typeref)
                    # follow through typedef/pointer layer until we find byte size attribute or base_type
                    visited = set()
                    while final and final.offset not in visited:
                        visited.add(final.offset)
                        b = attr_int(final, 'DW_AT_byte_size')
                        if b is not None:
                            member_size = b
                            break
                        # follow typedef/pointer/const to underlying type if present
                        next_ref = attr_int(final, 'DW_AT_type')
                        if next_ref:
                            final = die_map.get(next_ref)
                        else:
                            break
            except Exception:
                member_size = None

            members.append({
                'name': mname,
                'type': type_repr,
                'data_member_location': data_loc_val,
                'size': member_size,
            })

        results.append({
            'offset': hex(off),
            'name': struct_name,
            'size': struct_size,
            'members': members,
        })

    # Print summary
    
    for struct in results:
        # Compute struct alignment
        sdie = die_map[int(struct['offset'],16)]
        struct_align = get_member_alignment(die_map, sdie.offset)
        
        print(f"Struct @ {struct['offset']}: {struct['name']}" +
            (f" (size={struct['size']}, alignment={struct_align})" if struct['size'] is not None else ""))
        if not struct['members']:
            print("  <no members>")
        for m in struct['members']:
            loc = m['data_member_location']
            locs = f"offset={loc}" if loc is not None else "offset=?"
            size = f" size={m['size']}" if m['size'] is not None else ""
            print(f"  - {m['name']}: {m['type']}  ({locs}{size})")
        print()

    for struct in results:
        struct_list.append({
            'offset': struct['offset'],
            'name': struct['name'],
            'size': struct['size'],
            'members': struct['members']
        })

# write JSON
    with open("structs.json", "w") as f:
        json.dump(struct_list, f, indent=2)





def collect_structs(die_map):
    structs = []
    for die in die_map.values():
        if die.tag != 'DW_TAG_structure_type':
            continue
        members = [ch for ch in die.iter_children() if ch.tag == 'DW_TAG_member']
        if not members:
            continue  # skip empty
        size = attr_int(die, 'DW_AT_byte_size')
        align = get_member_alignment(die_map, die.offset)
        # Get name from DIE or typedef
        name = attr_str(die, 'DW_AT_name')
        if not name:
            # check typedefs pointing to this DIE
            for td in die_map.values():
                if td.tag == 'DW_TAG_typedef' and attr_int(td,'DW_AT_type') == die.offset:
                    name = attr_str(td,'DW_AT_name')
                    if name:
                        break
        if not name:
            name = f"<anon@0x{die.offset:x}>"

        structs.append({
            'die': die,
            'name': name,
            'size': size,
            'alignment': align,
            'members': members,
        })
    # Sort by alignment descending
    structs.sort(key=lambda x: x['alignment'], reverse=True)
    return structs


def print_heap_regions(elf):
    print("Heap-like writable segments:")
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD' and (seg['p_flags'] & 2):  # writable
            start = seg['p_vaddr']
            end = start + seg['p_memsz']
            print(f"  0x{start:x} - 0x{end:x}")


def get_member_alignment(die_map, type_offset, _seen=None):
    """Return byte alignment for a type DIE."""
    if type_offset is None:
        return 1

    if _seen is None:
        _seen = set()
    if type_offset in _seen:
        return 1
    _seen.add(type_offset)

    tdie = die_map.get(type_offset)
    if tdie is None:
        return 1

    # DW_AT_alignment if present
    align_attr = tdie.attributes.get('DW_AT_alignment')
    if align_attr:
        return align_attr.value

    # fallback: for base types, pointer types, array types, use byte size
    tag = tdie.tag
    if tag in ('DW_TAG_base_type', 'DW_TAG_pointer_type'):
        size = attr_int(tdie, 'DW_AT_byte_size')
        return size if size else 1

    if tag in ('DW_TAG_const_type','DW_TAG_volatile_type','DW_TAG_restrict_type','DW_TAG_typedef'):
        # recursively check underlying type
        return get_member_alignment(die_map, attr_int(tdie,'DW_AT_type'), _seen)

    if tag == 'DW_TAG_array_type':
        # alignment same as element type
        return get_member_alignment(die_map, attr_int(tdie,'DW_AT_type'), _seen)

    if tag in ('DW_TAG_structure_type','DW_TAG_union_type','DW_TAG_class_type'):
        # recursively compute max alignment of members
        max_align = 1
        for child in tdie.iter_children():
            if child.tag != 'DW_TAG_member':
                continue
            child_align = get_member_alignment(die_map, attr_int(child,'DW_AT_type'))
            if child_align > max_align:
                max_align = child_align
        return max_align

    # fallback
    return 1




def scan_heap_for_structs(heap_blob, base_addr, structs):
    """
    heap_blob: bytes object containing heap memory
    base_addr: virtual address corresponding to heap_blob[0]
    structs: list of structs sorted by alignment
    """
    heap_size = len(heap_blob)
    for struct in structs:
        size = struct['size']
        align = struct['alignment']
        name = struct['name']

        print(f"\nScanning for struct {name} (size={size}, align={align})")
        # iterate over heap with alignment
        for offset in range(0, heap_size - size + 1, align):
            mem_addr = base_addr + offset
            # candidate bytes
            candidate_bytes = heap_blob[offset:offset+size]

            # TODO: validate pointers/function pointers here
            # For now we just print candidate addresses
            print(f"  Candidate at 0x{mem_addr:x}")

# --- entry point ------------------------------------------------------------
def main(argv):
    if len(argv) != 2:
        print("Usage: dump_dwarf_structs.py <elf-file>")
        return 2

    path = argv[1]
    structure_list = []
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("No DWARF info found.")
            return 1
        dwarf = elf.get_dwarf_info()
        dump_structs(dwarf,structure_list)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
