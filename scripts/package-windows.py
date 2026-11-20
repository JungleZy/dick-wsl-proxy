#!/usr/bin/env python3
"""Assemble an offline, deterministic, unsigned Windows release (Python 3.11+)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tomllib
import zipfile

TARGET = "x86_64-pc-windows-gnu"
BINARIES = ("wsl-proxyctl.exe", "wsl-proxy-desktop.exe")
SCRIPTS = ("install.ps1", "uninstall.ps1", "common.ps1")
ROOT = Path(__file__).resolve().parent.parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pe_x64(data):
    require(len(data) >= 64 and data[:2] == b"MZ", "Not a PE executable")
    offset = struct.unpack_from("<I", data, 60)[0]
    require(offset + 26 <= len(data), "Truncated PE header")
    require(data[offset:offset + 4] == b"PE\0\0", "Invalid PE signature")
    require(struct.unpack_from("<H", data, offset + 4)[0] == 0x8664, "PE is not AMD64")
    require(struct.unpack_from("<H", data, offset + 24)[0] == 0x20b, "PE is not PE32+")
    require(struct.unpack_from("<H", data, offset + 22)[0] & 2, "PE is not executable")


def license_inventory(metadata, lock, payload):
    locked = {(p["name"], p["version"]) for p in lock["package"]}
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    pending = list(metadata["workspace_members"])
    visited = set()
    inventory = []
    issues = []
    while pending:
        ident = pending.pop()
        if ident in visited:
            continue
        visited.add(ident)
        require(ident in nodes and ident in packages, "Incomplete Cargo metadata graph")
        pending.extend(nodes[ident]["dependencies"])
        p = packages[ident]
        require((p["name"], p["version"]) in locked, "Metadata package absent from Cargo.lock: " + ident)
        if ident in metadata["workspace_members"]:
            continue
        name, version = p["name"], p["version"]
        require(re.fullmatch(r"[A-Za-z0-9_-]+", name) and re.fullmatch(r"[A-Za-z0-9_.+-]+", version), "Unsafe package identity")
        source_dir = Path(p["manifest_path"]).parent
        require(source_dir.is_dir(), "Offline crate source unavailable: " + ident)
        candidates = [f for f in source_dir.iterdir() if re.match(r"^(LICENSE|LICENCE|COPYING|NOTICE)([._-].*)?$", f.name, re.I)]
        if p.get("license_file"):
            candidates.append(source_dir / p["license_file"])
        notices = []
        for f in sorted(set(candidates)):
            require(f.is_file() and not f.is_symlink(), "Missing/unsafe license file: " + str(f))
            require(re.fullmatch(r"[A-Za-z0-9_.-]+", f.name) and ".." not in f.name, "Unsafe license filename")
            dest = f"licenses/{name}-{version}/{f.name}"
            data = f.read_bytes()
            require(dest not in payload or payload[dest] == data, "License filename collision")
            payload[dest] = data
            notices.append(dest)
        if not notices or not p.get("license"):
            issues.append(f"{name} {version}: missing license expression or local notice text")
        inventory.append({"name": name, "version": version, "source": p.get("source"), "license_expression": p.get("license"), "notices": notices})
    return {"status": "review-required", "reason": "Inventory is not a legal redistribution approval; review license obligations, native libraries and Rust/toolchain runtime notices separately.", "graph": "Conservative transitive Cargo metadata graph including build dependencies", "packages": sorted(inventory, key=lambda p: (p["name"], p["version"])), "issues": sorted(issues)}


def assemble(args):
    require(re.fullmatch(r"\d+\.\d+\.\d+", args.version), "Invalid version (expected numeric major.minor.patch)")
    require(not args.qa_vintage or args.version == "0.1.0", "Vintage fixture only supports 0.1.0")
    lock_bytes = (ROOT / "Cargo.lock").read_bytes()
    lock = tomllib.loads(lock_bytes.decode())
    record = json.loads(args.build_record.read_text())
    metadata = json.loads(args.cargo_metadata.read_text())
    require(record.get("schema_version") == 1, "Unsupported build record")
    require(record.get("version") == args.version and record.get("target") == TARGET, "Build record version/target mismatch")
    require(record.get("cargo_lock_sha256") == digest(lock_bytes), "Build record lock mismatch")
    require(metadata.get("resolve") is not None, "Cargo metadata requires resolved graph")
    if not args.qa_vintage:
        source = tomllib.loads((ROOT / "Cargo.toml").read_text())
        require(source["workspace"]["package"]["version"] == args.version, "Source workspace version mismatch")
        for p in metadata["packages"]:
            if p["id"] in metadata["workspace_members"]:
                require(p["version"] == args.version, "Metadata workspace version mismatch")
    payload = {}
    for name, path in zip(BINARIES, (args.backend, args.desktop)):
        data = path.read_bytes()
        pe_x64(data)
        item = record.get("binaries", {}).get(name, {})
        require(item.get("version") == args.version and item.get("sha256") == digest(data), "Recorded binary version/hash mismatch: " + name)
        payload[name] = data
    for name in SCRIPTS:
        path = ROOT / "packaging/windows" / name
        require(path.is_file() and not path.is_symlink(), "Missing installer script: " + name)
        payload[name] = path.read_bytes()
    payload["Cargo.lock"] = lock_bytes
    # Normalize the record to exclude incidental paths, timestamps, or arbitrary caller content.
    payload["BUILD-RECORD.json"] = json_bytes({"schema_version": 1, "version": args.version, "target": TARGET, "cargo_lock_sha256": digest(lock_bytes), "binaries": {n: {"version": args.version, "sha256": digest(payload[n])} for n in BINARIES}})
    licenses = license_inventory(metadata, lock, payload)
    payload["THIRD-PARTY-NOTICES.json"] = json_bytes(licenses)
    payload["USAGE.txt"] = ("WSL Proxy per-user Windows x64 package\n\nUnsigned: SHA256 verifies consistency, NOT publisher identity. No project license is inferred.\nThird-party redistribution approval is NOT established: inspect THIRD-PARTY-NOTICES.json and bundled license texts before redistribution. Native/toolchain notices require separate review.\n\nExtract to a fresh directory. Use PowerShell with existing permitted execution policy; do NOT bypass it.\n  .\\install.ps1 [-InstallDir path] [-AllowDowngrade] [-Recover]\n  .\\uninstall.ps1 [-InstallDir path] [-Recover]\nClose GUI first. An idle trusted broker may be gracefully shut down; active/recovery/foreign controllers refuse changes. Same-version exact manifest is a no-op; different same-version builds refuse. For interrupted operations rerun the matching script -Recover from the intact extracted package; never manually delete journals. No credentials or user profiles are bundled.\n\n" + ("QA VINTAGE FIXTURE ONLY: not a previously published installer. Old binary-to-source/lock linkage is unverified; license inventory describes supplied current source graph only.\n" if args.qa_vintage else "Build record is a caller declaration checked against binary hashes and source versions; it is not authenticated provenance. Verify backend --version on Windows before release acceptance.\n")).encode()
    manifest = {"schema_version": 1, "product": "wsl-proxy", "version": args.version, "target": TARGET, "architecture": "x64", "kind": "qa-vintage-not-published" if args.qa_vintage else "release-candidate", "payload": {"backend": BINARIES[0], "desktop": BINARIES[1]}, "files": [{"path": n, "sha256": digest(data), "size": len(data)} for n, data in sorted(payload.items())], "verification": {"pe_machine": "AMD64", "pe_format": "PE32+", "pair_compatibility": "same declared version, hashes bound by build record", "provenance": "caller-declared, unauthenticated", "binary_source_linkage": "unverified-vintage" if args.qa_vintage else "declared-build-record-and-source-version-consistency-only", "backend_host_version": "requires-independent-Windows-QA", "signed": False}, "licenses": {"status": "review-required", "inventory": "THIRD-PARTY-NOTICES.json", "missing_notice_count": len(licenses["issues"])}}
    payload["release.json"] = json_bytes(manifest)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / f"wsl-proxy-{args.version}-windows-x64.zip"
    require(not output.exists() and not output.with_suffix(".zip.sha256").exists(), "Output exists; choose a fresh named output directory")
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    sidecar = output.with_suffix(".zip.sha256")
    with sidecar.open("x", encoding="ascii", newline="\n") as stream:
        stream.write(f"{digest(output.read_bytes())}  {output.name}\n")
    print(output)
    print("LICENSE STATUS: review-required; no redistribution clearance asserted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("backend", "desktop", "build-record", "cargo-metadata", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--qa-vintage", action="store_true")
    try:
        assemble(parser.parse_args())
    except (ValueError, OSError, KeyError, TypeError, struct.error) as error:
        print(f"Packaging refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
