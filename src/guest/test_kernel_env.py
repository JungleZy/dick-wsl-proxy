"""Pure tests for the explicit kernel preparation helper.

These run without WSL: they cover the fixed module contract, the parsing of
kernel evidence, and the bounded failure reasons. The real load path is
exercised on the Windows side against an actual distribution.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernel_env


class BuiltinModules(unittest.TestCase):
    def test_reads_module_names_from_paths(self):
        text = (
            "kernel/net/netfilter/xt_cgroup.ko\n"
            "kernel/net/ipv4/netfilter/nf_nat.ko\n"
            "kernel/net/netfilter/xt_cgroup.modinfo\n"
            "\n"
        )
        self.assertEqual(
            kernel_env.builtin_names(text),
            {"xt_cgroup", "nf_nat"},
        )

    def test_normalizes_hyphenated_module_files(self):
        self.assertEqual(kernel_env.builtin_names("x/y/xt_foo-bar.ko\n"), {"xt_foo_bar"})


class TableNames(unittest.TestCase):
    def test_returns_sorted_valid_names_only(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="ascii") as handle:
            handle.write("nat\nfilter\nbad name\n\n")
            path = handle.name
        try:
            self.assertEqual(kernel_env.table_names(path), ["filter", "nat"])
        finally:
            os.unlink(path)

    def test_missing_proc_file_is_empty(self):
        self.assertEqual(kernel_env.table_names("/proc/does-not-exist-for-test"), [])


class Autoload(unittest.TestCase):
    def test_content_lists_the_proven_modules_under_a_header(self):
        text = kernel_env.autoload_content(["ip_tables", "xt_cgroup"])
        self.assertTrue(text.startswith("#"))
        self.assertIn("\nip_tables\nxt_cgroup\n", text)
        self.assertEqual(text.count("wsl-proxyctl"), 1)

    def test_rewriting_a_different_file_leaves_no_backup(self):
        # Decision 15: only the two files and the enable link, never a
        # .bak copy beside them.
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "modules-load.d", "wsl-proxy.conf")
            os.makedirs(os.path.dirname(path))
            with open(path, "w", encoding="ascii") as handle:
                handle.write("# older content\nnf_nat\n")
            with patch.object(kernel_env, "AUTOLOAD", path):
                result = kernel_env.write_autoload(["xt_cgroup", "nf_nat"])
            self.assertTrue(result["written"])
            self.assertIsNone(result["backup"])
            self.assertEqual(os.listdir(os.path.dirname(path)), ["wsl-proxy.conf"])
            with open(path, encoding="ascii") as handle:
                self.assertEqual(handle.read(), kernel_env.autoload_content(["xt_cgroup", "nf_nat"]))

    def test_the_persistent_path_is_fixed(self):
        self.assertEqual(
            kernel_env.AUTOLOAD,
            "/etc/modules-load.d/wsl-proxy.conf",
        )

    def test_the_boot_unit_initializes_tables_without_output(self):
        self.assertEqual(
            kernel_env.BOOT_UNIT,
            "/etc/systemd/system/wsl-proxy-tables.service",
        )
        text = kernel_env.BOOT_UNIT_CONTENT
        self.assertIn("WantedBy=sysinit.target", text)
        self.assertIn("iptables-legacy -t nat -S", text)
        self.assertIn("StandardOutput=null", text)
        self.assertIn("StandardError=null", text)


class ModuleState(unittest.TestCase):
    def test_builtin_module_does_not_need_sysfs(self):
        self.assertEqual(
            kernel_env.module_state("xt_cgroup", {"xt_cgroup"}),
            "builtin",
        )
        self.assertIsNone(kernel_env.module_state("xt_cgroup", set()))


class Reasons(unittest.TestCase):
    def test_reasons_are_bounded_and_single_line(self):
        self.assertEqual(kernel_env.printable("a\nb\tc"), "a b c")
        self.assertEqual(len(kernel_env.printable("x" * 400)), 160)
        self.assertNotIn("\x00", kernel_env.printable("a\x00b"))

    def test_empty_reason_is_empty(self):
        self.assertEqual(kernel_env.printable(""), "")


class Contract(unittest.TestCase):
    def test_module_contract_is_fixed_and_ordered(self):
        # `src/kernel_env.rs` rejects a response whose required modules differ,
        # so this list and order is a boundary, not an implementation detail.
        self.assertEqual(kernel_env.MODULES, (
            "ip_tables",
            "iptable_filter",
            "iptable_nat",
            "ip6_tables",
            "ip6table_filter",
            "ip6table_nat",
            "xt_cgroup",
            "xt_connmark",
            "xt_conntrack",
            "xt_comment",
            "xt_mark",
            "xt_nat",
        ))

    def test_only_filter_and_nat_are_registered(self):
        self.assertEqual(
            [(family, tables) for family, _, _, tables in kernel_env.TABLES],
            [("v4", ("filter", "nat")), ("v6", ("filter", "nat"))],
        )


if __name__ == "__main__":
    unittest.main()
