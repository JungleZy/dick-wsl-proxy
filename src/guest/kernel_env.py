"""Explicit preparation of the shared WSL kernel before a takeover.

The desktop runs this once, on the operator's request, when a cold WSL kernel
has no registered legacy netfilter tables or cgroup match. It only loads
module files that are already shipped with the running distribution and
registers empty legacy filter/nat tables. It never installs packages, writes
persistent configuration, adds or removes rules, or unloads a module. Every
command is fixed here; no request data crosses the boundary.
"""

import json
import os
import re
import shutil
import subprocess

PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
TIMEOUT = 8

# Fixed set the takeover rules need. Tables first, then the matches/targets
# registered by both address families.
MODULES = (
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
)

# (family, procfs table list, legacy tool, tables to register)
TABLES = (
    ("v4", "/proc/net/ip_tables_names", "iptables-legacy", ("filter", "nat")),
    ("v6", "/proc/net/ip6_tables_names", "ip6tables-legacy", ("filter", "nat")),
)

TABLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,15}$")


def read_text(path):
    try:
        with open(path, encoding="ascii", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def printable(text, limit=160):
    """One bounded single-line reason; never echo rule listings."""
    value = " ".join(str(text).split())
    value = "".join(character for character in value if " " <= character <= "~")
    return value[:limit]


def run(argv):
    """Run a fixed command. Only its status and stderr are kept."""
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT,
            env={"PATH": PATH, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        return 1, type(error).__name__
    return completed.returncode, printable(completed.stderr.decode("utf-8", "replace"))


def builtin_names(text):
    """Module names built into the kernel, from `modules.builtin`."""
    names = set()
    for line in text.splitlines():
        base = line.strip().rsplit("/", 1)[-1]
        if base.endswith(".ko"):
            names.add(base[:-3].replace("-", "_"))
    return names


def module_state(name, builtin):
    """`loaded`, `builtin`, or None when the module is not present yet."""
    if os.path.isdir("/sys/module/" + name):
        return "loaded"
    if name in builtin:
        return "builtin"
    return None


def table_names(path):
    return sorted(
        {
            line.strip()
            for line in read_text(path).splitlines()
            if TABLE_NAME.match(line.strip())
        }
    )


def load_modules(builtin):
    """Load every required module that is not already loaded or built in."""
    before = [name for name in MODULES if module_state(name, builtin)]
    added = []
    failed = []
    modprobe = shutil.which("modprobe", path=PATH)
    for name in MODULES:
        if module_state(name, builtin):
            continue
        if modprobe is None:
            failed.append({"module": name, "reason": "modprobe_missing"})
            continue
        status, error = run([modprobe, "-n", name])
        if status != 0:
            failed.append({
                "module": name,
                "reason": "not_available" + (":" + error if error else ""),
            })
            continue
        status, error = run([modprobe, name])
        if status != 0:
            failed.append({
                "module": name,
                "reason": "load_failed" + (":" + error if error else ""),
            })
            continue
        if module_state(name, builtin):
            added.append(name)
        else:
            failed.append({"module": name, "reason": "not_observed_after_load"})
    return before, added, failed


def register_tables(before):
    """Query each missing table once; the read-only dump makes the kernel
    register the empty table. Existing tables and rules are left untouched."""
    failures = []
    for family, proc, tool, wanted in TABLES:
        current = set(table_names(proc))
        for table in wanted:
            if table in current:
                continue
            status, error = run([tool, "-t", table, "-S"])
            if status != 0:
                failures.append({
                    "family": family,
                    "table": table,
                    "reason": printable(error) or "table_query_failed",
                })
            current = set(table_names(proc))
    after = {family: table_names(proc) for family, proc, _, _ in TABLES}
    added = {
        family: [table for table in after[family] if table not in before[family]]
        for family in ("v4", "v6")
    }
    return after, added, failures


def main():
    if os.geteuid() != 0:
        print(json.dumps({"ok": False, "error": "root_required"}))
        return
    release = read_text("/proc/sys/kernel/osrelease").strip()
    boot_id = read_text("/proc/sys/kernel/random/boot_id").strip()
    try:
        netns = os.readlink("/proc/self/ns/net")
    except OSError:
        netns = ""
    modules_dir = bool(release) and os.path.isdir("/lib/modules/" + release)
    builtin = builtin_names(
        read_text("/lib/modules/" + release + "/modules.builtin") if release else ""
    )
    before_tables = {family: table_names(proc) for family, proc, _, _ in TABLES}
    before_modules, added, failed = load_modules(builtin)
    after_tables, added_tables, table_failures = register_tables(before_tables)
    print(json.dumps({
        "ok": True,
        "kernel_release": release,
        "boot_id": boot_id,
        "netns": netns,
        "modules_dir": modules_dir,
        "modules_required": list(MODULES),
        "modules_before": before_modules,
        "modules_added": added,
        "modules_failed": failed,
        "tables": {
            "before": before_tables,
            "after": after_tables,
            "added": added_tables,
        },
        "table_failures": table_failures,
    }, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"ok": False, "error": "internal_error"}))
