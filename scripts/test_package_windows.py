"""Focused packaging checks; run: python3 -m unittest discover -s scripts -p 'test_package_windows.py'."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("package_windows", Path(__file__).with_name("package-windows.py"))
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)


def pe(machine=0x8664):
    data = bytearray(256)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<H", data, 132, machine)
    struct.pack_into("<H", data, 150, 2)
    struct.pack_into("<H", data, 152, 0x20b)
    return bytes(data)


def edge(pkg, *kinds):
    return {"pkg": pkg, "dep_kinds": [{"kind": kind, "target": None} for kind in kinds]}


def normal(pkg):
    return edge(pkg, None)


class LicenseTests(unittest.TestCase):
    """The third-party inventory covers what the executables link, and fills in
    a standard text only where a package ships none and offers a license we carry."""

    def inventory(self, crates, edges):
        """crates: name -> (license, files); edges: member/crate -> [edge]."""
        with tempfile.TemporaryDirectory(prefix="wsl-proxy-license-test-") as temporary:
            root = Path(temporary)
            packages = [{"id": "member", "name": "wsl-proxyctl", "version": "0.1.1", "manifest_path": str(root / "Cargo.toml")}]
            lock = {"package": [{"name": "wsl-proxyctl", "version": "0.1.1"}]}
            for name, (license, files) in crates.items():
                (root / name).mkdir()
                for file, text in files.items():
                    (root / name / file).write_text(text, newline="\n")
                packages.append({"id": name, "name": name, "version": "1.0.0", "manifest_path": str(root / name / "Cargo.toml"), "source": "registry+test", "license": license, "authors": ["Example Author <author@example.invalid>"]})
                lock["package"].append({"name": name, "version": "1.0.0"})
            metadata = {"packages": packages, "workspace_members": ["member"], "resolve": {"nodes": [{"id": p["id"], "deps": edges.get(p["id"], [])} for p in packages]}}
            payload = {}
            return pack.license_inventory(metadata, lock, payload), payload

    def test_reads_plain_choices_and_leaves_compound_expressions_to_a_person(self):
        self.assertEqual(pack.license_options("MIT OR Apache-2.0"), ["MIT", "Apache-2.0"])
        self.assertEqual(pack.license_options("MIT/Apache-2.0"), ["MIT", "Apache-2.0"])
        self.assertEqual(pack.license_options("Apache-2.0"), ["Apache-2.0"])
        self.assertIsNone(pack.license_options("(MIT OR Apache-2.0) AND Unicode-3.0"))
        self.assertIsNone(pack.license_options("Apache-2.0 WITH LLVM-exception OR MIT"))

    def test_covers_only_what_the_executables_link(self):
        crates = {name: ("MIT", {"LICENSE": name}) for name in ("linked", "build-only", "dev-only", "both", "below-build")}
        edges = {
            "member": [normal("linked"), edge("build-only", "build"), edge("dev-only", "dev"), edge("both", "build", None)],
            "build-only": [normal("below-build")],
        }
        inventory, _ = self.inventory(crates, edges)
        self.assertEqual([p["name"] for p in inventory["packages"]], ["both", "linked"])
        self.assertEqual(inventory["issues"], [])

    def test_fills_in_the_standard_text_only_for_a_license_we_carry(self):
        crates = {
            "ships-file": ("MIT", {"LICENSE-MIT": "Own text\n"}),
            "mit-or-apache": ("MIT OR Apache-2.0", {}),
            "apache-only": ("Apache-2.0", {}),
            "bsd-only": ("BSD-3-Clause", {}),
            "compound": ("(MIT OR Apache-2.0) AND Unicode-3.0", {}),
        }
        inventory, payload = self.inventory(crates, {"member": [normal(name) for name in crates]})
        by_name = {p["name"]: p for p in inventory["packages"]}
        self.assertEqual(by_name["ships-file"]["notice_kind"], "crate-file")
        self.assertEqual(payload["licenses/ships-file-1.0.0/LICENSE-MIT"], b"Own text\n")
        mit = payload["licenses/mit-or-apache-1.0.0/MIT.txt"].decode()
        self.assertEqual((by_name["mit-or-apache"]["notice_kind"], by_name["mit-or-apache"]["redistributed_under"]), ("standard-text", "MIT"))
        self.assertIn('declares the license\n"MIT OR Apache-2.0"', mit)
        self.assertIn("Copyright (c) Example Author <author@example.invalid>", mit)
        self.assertIn("Permission is hereby granted, free of charge", mit)
        apache = payload["licenses/apache-only-1.0.0/Apache-2.0.txt"].decode()
        self.assertIn("Apache License\n                        Version 2.0, January 2004", apache)
        self.assertNotIn("Copyright (c) Example Author", apache)
        self.assertEqual(inventory["standard_text_count"], 2)
        self.assertEqual(inventory["issues"], [
            "bsd-only 1.0.0: missing license expression or local notice text",
            "compound 1.0.0: missing license expression or local notice text",
        ])

    def test_refuses_metadata_without_dependency_kinds(self):
        metadata = {"packages": [{"id": "member", "name": "wsl-proxyctl", "version": "0.1.1", "manifest_path": "Cargo.toml"}], "workspace_members": ["member"], "resolve": {"nodes": [{"id": "member", "dependencies": []}]}}
        with self.assertRaises(ValueError):
            pack.license_inventory(metadata, {"package": [{"name": "wsl-proxyctl", "version": "0.1.1"}]}, {})


class PackagingTests(unittest.TestCase):
    def test_reads_json_records_regardless_of_the_windows_code_page(self):
        value = {"schema_version": 1, "note": "中文"}
        text = json.dumps(value, ensure_ascii=False)
        with tempfile.TemporaryDirectory(prefix="wsl-proxy-package-test-") as temporary:
            for name, data in (
                ("plain.json", text.encode("utf-8")),
                ("bom.json", text.encode("utf-8-sig")),
                ("powershell.json", text.encode("utf-16")),
            ):
                path = Path(temporary) / name
                path.write_bytes(data)
                self.assertEqual(pack.read_json(path), value)

    def test_rejects_wrong_architecture_and_truncation(self):
        for data in (pe(0x14c), b"MZ", b"not executable"):
            with self.assertRaises(ValueError):
                pack.pe_x64(data)

    def test_repeatability_allowlist_hashes_and_refusals(self):
        with tempfile.TemporaryDirectory(prefix="wsl-proxy-package-test-") as temporary:
            root = Path(temporary)
            (root / "desktop").mkdir()
            (root / "packaging/windows").mkdir(parents=True)
            (root / "Cargo.toml").write_text("[workspace]\nmembers=[\"desktop\"]\n\n[workspace.package]\nversion=\"0.1.1\"\nedition=\"2024\"\npublish=false\n\n[package]\nname=\"wsl-proxyctl\"\nversion.workspace=true\nedition.workspace=true\npublish.workspace=true\n")
            (root / "desktop/Cargo.toml").write_text("[package]\nname=\"wsl-proxy-desktop\"\nversion.workspace=true\nedition.workspace=true\npublish.workspace=true\n")
            (root / "Cargo.lock").write_text('version=4\n[[package]]\nname="wsl-proxyctl"\nversion="0.1.1"\n[[package]]\nname="wsl-proxy-desktop"\nversion="0.1.1"\n[[package]]\nname="example-dep"\nversion="1.0.0"\n')
            crate = root / "local-crate"
            crate.mkdir()
            (crate / "LICENSE-MIT").write_text("Actual test notice text\n", newline="\n")
            for name in pack.SCRIPTS:
                (root / "packaging/windows" / name).write_text("# test fixture script\n")
            (root / ".env").write_text("MUST_NOT_BUNDLE=secret")
            for name in pack.BINARIES:
                (root / name).write_bytes(pe())
            packages = [{"id": name, "name": name, "version": "0.1.1", "manifest_path": str(root / "Cargo.toml")} for name in ("wsl-proxyctl", "wsl-proxy-desktop")]
            packages.append({"id": "dep", "name": "example-dep", "version": "1.0.0", "manifest_path": str(crate / "Cargo.toml"), "source": "registry+test", "license": "MIT"})
            metadata = {"packages": packages, "workspace_members": ["wsl-proxyctl", "wsl-proxy-desktop"], "resolve": {"nodes": [{"id": p["id"], "deps": [normal("dep")] if p["id"] != "dep" else []} for p in packages]}}
            (root / "metadata.json").write_text(json.dumps(metadata))
            record = {"schema_version": 1, "version": "0.1.1", "target": pack.TARGET, "cargo_lock_sha256": pack.digest((root / "Cargo.lock").read_bytes()), "binaries": {name: {"version": "0.1.1", "sha256": pack.digest(pe())} for name in pack.BINARIES}}
            (root / "record.json").write_text(json.dumps(record))
            args = argparse.Namespace(backend=root / pack.BINARIES[0], desktop=root / pack.BINARIES[1], version="0.1.1", build_record=root / "record.json", cargo_metadata=root / "metadata.json", output_dir=root / "one", qa_vintage=False)
            with patch.object(pack, "ROOT", root):
                pack.assemble(args)
                with self.assertRaises(ValueError):
                    pack.assemble(args)
                args.output_dir = root / "two"
                pack.assemble(args)
                name = "wsl-proxy-0.1.1-windows-x64.zip"
                self.assertEqual((root / "one" / name).read_bytes(), (root / "two" / name).read_bytes())
                with zipfile.ZipFile(root / "one" / name) as archive:
                    self.assertNotIn(".env", archive.namelist())
                    manifest = json.loads(archive.read("release.json"))
                    self.assertEqual(set(archive.namelist()), {p["path"] for p in manifest["files"]} | {"release.json"})
                    for item in manifest["files"]:
                        data = archive.read(item["path"])
                        self.assertEqual(item["sha256"], pack.digest(data))
                        self.assertEqual(item["size"], len(data))
                    self.assertEqual(archive.read("licenses/example-dep-1.0.0/LICENSE-MIT"), b"Actual test notice text\n")
                record["binaries"][pack.BINARIES[0]]["sha256"] = "0" * 64
                (root / "record.json").write_text(json.dumps(record))
                args.output_dir = root / "refused"
                with self.assertRaises(ValueError):
                    pack.assemble(args)
                self.assertFalse(args.output_dir.exists())


if __name__ == "__main__":
    unittest.main()
