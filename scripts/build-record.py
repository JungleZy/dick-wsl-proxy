#!/usr/bin/env python3
"""Write the build record that scripts/package-windows.py checks.

It declares the release version, the MSVC target, the Cargo.lock digest and
both executables' digests. It is the caller's declaration, not authenticated
provenance (see docs/plans/m5/README.md).

Usage: build-record.py --version X.Y.Z --backend EXE --desktop EXE --output JSON
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
TARGET = "x86_64-pc-windows-msvc"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ("version", "backend", "desktop", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    record = {
        "schema_version": 1,
        "version": args.version,
        "target": TARGET,
        "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
        "binaries": {
            "wsl-proxyctl.exe": {"version": args.version, "sha256": digest(args.backend)},
            "wsl-proxy-desktop.exe": {"version": args.version, "sha256": digest(args.desktop)},
        },
    }
    with open(args.output, "x", encoding="utf-8") as handle:
        json.dump(record, handle, indent=1)
        handle.write("\n")
    print(json.dumps(record, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
