#!/usr/bin/env python3
"""Fail when a Windows x64 executable imports a C runtime DLL.

The release EXEs link the C runtime statically (`.cargo/config.toml`), so they
must not import VCRUNTIME*, MSVCP*, UCRTBASE, MSVCR* or api-ms-win-crt-*. A
machine that already has the Visual C++ runtime runs a dynamically linked EXE
just as well, so only the import table can show this. Both normal and
delay-load imports are read.

Usage: check-windows-imports.py [--json OUT] EXE [EXE ...]
Exit status 0 when no EXE imports a C runtime DLL, 1 otherwise or on a bad PE.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

C_RUNTIME = ("vcruntime", "msvcp", "msvcr", "ucrtbase", "api-ms-win-crt-")


def imports(data):
    """{"import": [...], "delay": [...]} DLL names of a PE32+ image."""
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("not a PE executable")
    pe = struct.unpack_from("<I", data, 60)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("not PE32+")
    directories = optional + 112
    table = []
    for index in range(sections):
        header = optional + optional_size + 40 * index
        virtual_size, address, raw_size, raw = struct.unpack_from("<IIII", data, header + 8)
        table.append((address, max(virtual_size, raw_size), raw))

    def offset(rva):
        for address, size, raw in table:
            if address <= rva < address + size:
                return raw + rva - address
        raise ValueError(f"RVA {rva:#x} outside every section")

    def name(rva):
        start = offset(rva)
        return data[start:data.index(b"\0", start)].decode("ascii")

    result = {}
    # Import directory (index 1, 20-byte descriptors, name at +12) and
    # delay-load directory (index 13, 32-byte descriptors, name at +4).
    for kind, index, size, name_at in (("import", 1, 20, 12), ("delay", 13, 32, 4)):
        rva = struct.unpack_from("<I", data, directories + 8 * index)[0]
        names = []
        if rva:
            cursor = offset(rva)
            while data[cursor:cursor + size] != b"\0" * size:
                names.append(name(struct.unpack_from("<I", data, cursor + name_at)[0]))
                cursor += size
        result[kind] = sorted(names, key=str.lower)
    return result


def c_runtime(names):
    return [name for name in names if name.lower().startswith(C_RUNTIME)]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", type=Path, help="also write the report here")
    parser.add_argument("executables", type=Path, nargs="+")
    args = parser.parse_args()
    report, failed = {}, False
    for path in args.executables:
        try:
            found = imports(path.read_bytes())
        except (OSError, ValueError, struct.error) as error:
            report[path.name] = {"error": str(error)}
            failed = True
            continue
        found["c_runtime"] = c_runtime(found["import"] + found["delay"])
        failed |= bool(found["c_runtime"])
        report[path.name] = found
    text = json.dumps(report, indent=1)
    print(text)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    if failed:
        print("C runtime DLL imported or unreadable executable: release refused", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
