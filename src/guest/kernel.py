"""Ephemeral, authenticated guest operations; no helper is installed in the guest."""

from contextlib import contextmanager
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time

GRANT_DIRECTORY = "/run/wsl-proxyctl-m3"


class Failure(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Failure(reason)


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def uuid(value, braces=False):
    pattern = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
    if braces:
        pattern = r"\{" + pattern + r"\}"
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def decimal(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None
        and int(value) <= 0xffffffffffffffff
    )


def text(value, maximum):
    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= maximum
        and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
    )


def unicast(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        return False
    first, second, _, _ = address.packed
    return str(address) == value and first not in (0, 127) and first < 224 and not (first == 169 and second == 254)


def endpoint(value):
    require(isinstance(value, str) and value.count(":") == 1, "invalid_endpoint")
    address, port = value.split(":")
    require(unicast(address) and decimal(port) and int(port) <= 65535, "invalid_endpoint")
    return address, int(port)


def endpoint6(value):
    require(isinstance(value, str) and value.startswith("[") and "]:" in value, "invalid_ipv6_endpoint")
    address, port = value[1:].rsplit("]:", 1)
    try:
        parsed = ipaddress.IPv6Address(address.split("%", 1)[0])
    except (ValueError, TypeError):
        raise Failure("invalid_ipv6_endpoint")
    require(
        not parsed.is_unspecified
        and not parsed.is_multicast
        and not parsed.is_loopback
        and parsed.ipv4_mapped is None,
        "invalid_ipv6_endpoint",
    )
    require(decimal(port) and int(port) <= 65535, "invalid_ipv6_endpoint")
    return str(parsed), int(port)


def validate(request):
    fields = {"operation", "plan", "protocol", "peer"}
    require(isinstance(request, dict) and set(request) in (fields, fields | {"deadline"}), "invalid_request")
    operation = request["operation"]
    require(operation in ("precheck", "arm", "install", "remove", "inspect", "lookup", "sync_networks", "block"), "invalid_operation")
    require((operation == "arm") == ("deadline" in request), "unexpected_or_missing_grant_deadline")
    if operation == "arm":
        require(integer(request["deadline"], 1, 0xffffffffffffffff), "invalid_grant_deadline")
    p = request["plan"]
    fields = {"target", "cgroup_ns", "cgroup_root", "boot_id", "guest", "ingress", "origins", "cookie"}
    allowed_plan = fields | {"system_dns", "ipv6"}
    require(isinstance(p, dict) and set(p) in (fields, fields | {"system_dns"}, allowed_plan, allowed_plan - {"system_dns"}), "invalid_plan")
    if "ipv6" in p:
        ipv6 = p["ipv6"]
        require(isinstance(ipv6, dict) and set(ipv6) == {"guest", "ingress"}, "invalid_ipv6_plan")
        guest6 = endpoint6("[" + ipv6["guest"] + "]:1")[0]
        ingress6 = endpoint6(ipv6["ingress"])
        require(
            "system_dns" in p
            and guest6 != ingress6[0]
            and ingress6[1] >= 1024,
            "invalid_ipv6_plan",
        )
    require("system_dns" not in p or unicast(p["system_dns"]), "invalid_system_dns")
    target = p["target"]
    require(isinstance(target, dict) and set(target) == {"id", "name", "base_path", "version"}, "invalid_target")
    require(uuid(target["id"], True) and text(target["name"], 256) and text(target["base_path"], 32768) and type(target["version"]) is int and target["version"] == 2, "invalid_registered_identity")
    require(uuid(p["boot_id"]), "invalid_boot_id")
    require(isinstance(p["cgroup_ns"], str) and re.fullmatch(r"cgroup:\[([1-9][0-9]{0,19})\]", p["cgroup_ns"]) is not None and decimal(p["cgroup_ns"][8:-1]), "invalid_cgroup_namespace")
    root = p["cgroup_root"]
    require(isinstance(root, str) and root.count(":") == 1 and all(decimal(value) for value in root.split(":")), "invalid_cgroup_root")
    require(integer(p["cookie"], 1, 0xffffffff) and unicast(p["guest"]), "invalid_instance")
    ingress = endpoint(p["ingress"])
    require(ingress[0] != p["guest"] and ingress[1] >= 1024, "invalid_ingress")
    require(isinstance(p["origins"], list) and len(p["origins"]) <= 8 and all(isinstance(value, str) for value in p["origins"]) and len(set(p["origins"])) == len(p["origins"]), "invalid_origins")
    require(bool(p["origins"]) != (p.get("system_dns") is not None), "invalid_mode_origins")
    origins = [endpoint(value) for value in p["origins"]]
    require(all(address in (ingress[0], p["guest"]) and port >= 1024 and port != ingress[1] for address, port in origins), "nonlocal_or_nonbusiness_origin")
    if operation == "lookup":
        require(request["protocol"] in ("tcp", "udp"), "invalid_lookup_protocol")
        if isinstance(request["peer"], str) and request["peer"].startswith("["):
            peer = endpoint6(request["peer"])
            require("ipv6" in p and peer[0] == endpoint6("[" + p["ipv6"]["guest"] + "]:1")[0], "invalid_lookup_peer")
        else:
            peer = endpoint(request["peer"])
            require(peer[0] == p["guest"], "invalid_lookup_peer")
    else:
        require(request["protocol"] is None and request["peer"] is None, "unexpected_lookup_parameters")
    return p


def read_text(path):
    with open(path, encoding="ascii") as handle:
        return handle.read().strip()


def cgroup_path(path):
    lines = read_text(path).splitlines()
    unified = [line[3:] for line in lines if line.startswith("0::")]
    require(len(unified) == 1 and unified[0].startswith("/"), "nonunified_cgroup")
    return unified[0]


def run(argv, data=None, timeout=4):
    try:
        result = subprocess.run(argv, input=data, text=True, encoding="utf-8", capture_output=True, timeout=timeout, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Failure("tool_unavailable_or_timeout: " + argv[0]) from error
    require(result.returncode == 0, "tool_failed: " + argv[0] + ": " + result.stderr.strip()[:1200])
    require(len(result.stdout) <= 16 * 1024 * 1024, "tool_output_limit")
    return result.stdout


def guard(p, check_resolver=True, write_tools=True):
    require(os.geteuid() == 0, "root_required")
    require(os.environ.get("WSL_DISTRO_NAME") == p["target"]["name"], "distribution_name_changed")
    require(read_text("/proc/sys/kernel/random/boot_id") == p["boot_id"], "boot_changed")
    require(os.readlink("/proc/self/ns/cgroup") == p["cgroup_ns"] and os.readlink("/proc/1/ns/cgroup") == p["cgroup_ns"], "cgroup_namespace_changed")
    mounts = [line.split() for line in read_text("/proc/self/mountinfo").splitlines() if " - cgroup2 " in line]
    require(len(mounts) == 1, "cgroup_mount_ambiguous")
    mount = mounts[0]
    require(mount[3] == "/" and mount[4] == "/sys/fs/cgroup", "unsupported_cgroup_mount")
    root = os.stat("/sys/fs/cgroup", follow_symlinks=False)
    require(stat.S_ISDIR(root.st_mode) and f"{root.st_dev}:{root.st_ino}" == p["cgroup_root"], "cgroup_root_changed")
    require(".." not in cgroup_path("/proc/1/cgroup").split("/"), "pid1_outside_distro_cgroup")
    require(".." not in cgroup_path("/proc/self/cgroup").split("/"), "controller_outside_distro_cgroup")
    # WSL infrastructure may sit above the distro root; every actual workload
    # must remain inside the same namespace root used by xt_cgroup --path /.
    init = os.stat("/init")
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            path = cgroup_path(entry.path + "/cgroup")
            if ".." in path.split("/"):
                executable = os.stat(entry.path + "/exe")
                require((executable.st_dev, executable.st_ino) == (init.st_dev, init.st_ino), "workload_outside_distro_cgroup")
        except (FileNotFoundError, ProcessLookupError):
            require(not os.path.exists(entry.path), "unverifiable_workload")
    for command in (("ip", "iptables-legacy-save", "iptables-legacy-restore") if write_tools else ("ip", "iptables-legacy-save")):
        require(shutil.which(command, path="/usr/sbin:/usr/bin:/sbin:/bin") is not None, "missing_prerequisite: " + command)
    addresses = json.loads(run(["ip", "-j", "-4", "address", "show", "dev", "eth0"]))
    require(isinstance(addresses, list) and len(addresses) == 1, "guest_interface_ambiguous")
    locals_ = [item.get("local") for item in addresses[0].get("addr_info", []) if item.get("family") == "inet" and item.get("scope") == "global"]
    require(locals_ == [p["guest"]], "guest_address_changed")
    routes = json.loads(run(["ip", "-j", "-4", "route", "show", "default"]))
    require(isinstance(routes, list) and len(routes) == 1 and routes[0].get("dev") == "eth0" and routes[0].get("gateway") == endpoint(p["ingress"])[0], "gateway_changed_or_ambiguous")
    if p.get("system_dns") is not None:
        for command in (("ip6tables-legacy-save", "ip6tables-legacy-restore") if write_tools else ("ip6tables-legacy-save",)):
            require(shutil.which(command, path="/usr/sbin:/usr/bin:/sbin:/bin") is not None, "missing_prerequisite: " + command)
        if check_resolver:
            resolver_layout(p, read_text("/etc/resolv.conf"))
    if p.get("ipv6") is not None:
        addresses6 = json.loads(run(["ip", "-j", "-6", "address", "show", "dev", "eth0"]))
        require(isinstance(addresses6, list) and len(addresses6) == 1, "guest_ipv6_interface_ambiguous")
        globals6 = [
            item.get("local")
            for item in addresses6[0].get("addr_info", [])
            if item.get("family") == "inet6" and item.get("scope") == "global"
        ]
        require(globals6 == [p["ipv6"]["guest"]], "guest_ipv6_address_changed")
        routes6 = json.loads(run(["ip", "-j", "-6", "route", "show", "default"]))
        require(
            isinstance(routes6, list)
            and len(routes6) == 1
            and routes6[0].get("dev") == "eth0"
            and routes6[0].get("gateway") == endpoint6(p["ipv6"]["ingress"])[0],
            "ipv6_gateway_changed_or_ambiguous",
        )
        ingress_address = p["ipv6"]["ingress"][1:].rsplit("]:", 1)[0]
        raw_address, _, scope = ingress_address.partition("%")
        if ipaddress.IPv6Address(raw_address).is_unicast_link_local:
            require(scope.isdigit() and int(scope) > 0, "ipv6_ingress_scope_missing")
        else:
            require(not scope, "ipv6_ingress_scope_unexpected")


@contextmanager
def guest_lock():
    # Lock the existing directory inode: read-only inspection never creates a
    # lock file, and remove cannot attest absence before an in-flight install.
    require(os.geteuid() == 0, "root_required")
    descriptor = os.open("/run", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        require(info.st_uid == 0 and not info.st_mode & 0o022, "unsafe_lock_directory")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def plan_digest(p):
    return hashlib.sha256(json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def read_grant(descriptor):
    info = os.fstat(descriptor)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "unsafe_grant_file")
    require(info.st_size <= 1024, "invalid_install_grant")
    value = json.loads(os.read(descriptor, 1025).decode("ascii"))
    require(isinstance(value, dict) and set(value) == {"state", "deadline"} and value["state"] in ("armed", "consumed", "revoked") and integer(value["deadline"], 1, 0xffffffffffffffff), "invalid_install_grant")
    return value


def prune_grants(directory, keep):
    # Only mutators GC control metadata; expired files never authorize install.
    now = time.time()
    for name in os.listdir(directory):
        require(re.fullmatch(r"[0-9a-f]{64}\.json", name) is not None, "unexpected_grant_entry")
        if name == keep:
            continue
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "unsafe_grant_file")
            try:
                expired = read_grant(descriptor)["deadline"] <= now
            except (Failure, ValueError, UnicodeError):
                # An interrupted write cannot authorize install; its last write
                # bounds every previously accepted 30-second arm deadline.
                expired = info.st_mtime + 30 <= now
            if expired:
                os.unlink(name, dir_fd=directory)
        finally:
            os.close(descriptor)


def grant(p, action, deadline=None):
    # The host arms each immutable Plan once, only after journal persistence.
    # A normal stop removes its observed ticket; an uncertain arm is fenced by
    # a 30-second revoked record, GC'd by a later mutator (never by inspect).
    if action != "consume":
        try:
            os.mkdir(GRANT_DIRECTORY, 0o700)
        except FileExistsError:
            pass
    try:
        directory = os.open(GRANT_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError as error:
        raise Failure("install_grant_missing") from error
    safe_directory = False
    try:
        info = os.fstat(directory)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "unsafe_grant_directory")
        safe_directory = True
        name = plan_digest(p) + ".json"
        prune_grants(directory, name)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        if action == "arm":
            require(int(time.time()) < deadline <= int(time.time()) + 30, "install_grant_expired_or_clock_changed")
            flags |= os.O_CREAT | os.O_EXCL
        elif action == "revoke":
            flags |= os.O_CREAT
        else:
            require(action == "consume", "invalid_grant_action")
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory)
        except FileExistsError as error:
            raise Failure("install_grant_already_used_or_revoked") from error
        except FileNotFoundError as error:
            raise Failure("install_grant_missing") from error
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "unsafe_grant_file")
            if action in ("consume", "revoke"):
                try:
                    previous = read_grant(descriptor)
                except (Failure, ValueError, UnicodeError):
                    if action == "consume":
                        raise
                    previous = None
                if action == "revoke":
                    if previous and (previous["state"] in ("armed", "consumed") or previous["deadline"] <= int(time.time())):
                        os.unlink(name, dir_fd=directory)
                        return
                    deadline = int(time.time()) + 30
                else:
                    require(previous["state"] == "armed" and int(time.time()) < previous["deadline"], "install_grant_expired_used_or_revoked")
                    deadline = previous["deadline"]
            value = {"state": {"arm": "armed", "consume": "consumed", "revoke": "revoked"}[action], "deadline": deadline}
            encoded = json.dumps(value, separators=(",", ":")).encode("ascii")
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            require(os.write(descriptor, encoded) == len(encoded), "install_grant_write_incomplete")
        finally:
            os.close(descriptor)
    finally:
        empty = safe_directory and not os.listdir(directory)
        os.close(directory)
        if empty:
            os.rmdir(GRANT_DIRECTORY)


def grant_pending(p):
    # Inspection opens only existing files; it neither renews nor revokes grants.
    try:
        directory = os.open(GRANT_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    try:
        info = os.fstat(directory)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "unsafe_grant_directory")
        try:
            descriptor = os.open(plan_digest(p) + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        except FileNotFoundError:
            return False
        try:
            value = read_grant(descriptor)
            return value["state"] == "armed" and int(time.time()) < value["deadline"]
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def resolver_layout(p, content):
    resolvers = [line.split()[1:] for line in content.splitlines() if line.split() and line.split()[0] == "nameserver"]
    require(resolvers == [[p["system_dns"]]], "unsupported_or_changed_resolver_layout")


def artifacts(p):
    if p.get("system_dns") is not None:
        return m2_artifacts(p)
    cookie = f"{p['cookie']:08x}"
    chain = "WPM1_" + cookie
    digest = plan_digest(p)[:16]
    tag = "wsl-proxyctl-m1:" + cookie + ":" + digest
    mark = f"0x{p['cookie']:x}"
    comment = ["-m", "comment", "--comment", tag]
    body = [
        ["-A", chain, "-m", "connmark", "--mark", "0x0", *comment, "-j", "CONNMARK", "--set-xmark", mark + "/0xffffffff"],
        ["-A", chain, "-p", "tcp", "-m", "connmark", "--mark", mark, *comment, "-j", "DNAT", "--to-destination", p["ingress"]],
        ["-A", chain, "-p", "udp", "-m", "connmark", "--mark", mark, *comment, "-j", "DNAT", "--to-destination", p["ingress"]],
        ["-A", chain, *comment, "-j", "MARK", "--set-xmark", mark + "/0xffffffff"],
    ]
    hooks, guards = [], []
    for origin in p["origins"]:
        address, port = endpoint(origin)
        for protocol in ("tcp", "udp"):
            match = ["-s", p["guest"] + "/32", "-d", address + "/32", "-p", protocol, "-m", protocol, "--dport", str(port), "-m", "cgroup", "--path", "/", "-m", "conntrack", "--ctstate", "NEW", "--ctdir", "ORIGINAL"]
            hooks.append(["-A", "OUTPUT", *match, *comment, "-j", chain])
            guard_match = ["-s", p["guest"] + "/32", "-p", protocol, "-m", "cgroup", "--path", "/", "-m", "conntrack", "--ctstate", "NEW", "--ctdir", "ORIGINAL", "--ctorigsrc", p["guest"], "--ctorigdst", address, "--ctorigdstport", str(port)]
            guards.append(["-A", "OUTPUT", *guard_match, "-m", "mark", "--mark", mark, *comment, "-j", "DROP"])
    return chain, tag, hooks, body, guards


def m2_artifacts(p):
    cookie = f"{p['cookie']:08x}"
    chain, guard_chain = "WPM2_" + cookie, "WPM2G_" + cookie
    bridge_chain, forward_chain, forward_bridges = "WPM2B_" + cookie, "WPM2F_" + cookie, "WPM2FB_" + cookie
    digest = plan_digest(p)[:16]
    tag = "wsl-proxyctl-m2:" + cookie + ":" + digest
    comment = ["-m", "comment", "--comment", tag]
    mark = f"0x{p['cookie']:x}"
    ingress, ingress_port = endpoint(p["ingress"])
    local = ["-m", "cgroup", "--path", "/"]
    fresh = ["-m", "conntrack", "--ctstate", "NEW", "--ctdir", "ORIGINAL"]
    hooks, body = [], []
    # These exclusions precede marking: a direct forged ingress packet can
    # never acquire an owned original-destination proof.
    for protocol in ("tcp", "udp"):
        body.append(["-A", chain, "-d", ingress + "/32", "-p", protocol, "-m", protocol, "--dport", str(ingress_port), *comment, "-j", "RETURN"])
    for network in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"):
        body.append(["-A", chain, "-d", network, *comment, "-j", "RETURN"])
    # Non-local traffic (container bridges) for a resolver other than the
    # system one is not redirected (decision 20). `Ownership.owned` could never
    # prove such a mapping, so one marked would turn the whole takeover into a
    # protection loss although the ingress refuses it anyway. Left unmarked,
    # it meets the FORWARD guard's final DROP and never leaves directly.
    for protocol in ("tcp", "udp"):
        body.append(["-A", chain, "!", "-s", p["guest"] + "/32", "!", "-d", p["system_dns"] + "/32", "-p", protocol, "-m", protocol, "--dport", "53", *comment, "-j", "RETURN"])
    body.extend([
        ["-A", chain, "-m", "connmark", "--mark", "0x0", *comment, "-j", "CONNMARK", "--set-xmark", mark + "/0xffffffff"],
        ["-A", chain, "-p", "tcp", "-m", "connmark", "--mark", mark, *comment, "-j", "DNAT", "--to-destination", p["ingress"]],
        ["-A", chain, "-p", "udp", "-m", "connmark", "--mark", mark, *comment, "-j", "DNAT", "--to-destination", p["ingress"]],
        # Per-network rules for the target's own container bridges go in
        # front of this; anything else (other distributions' containers in
        # the shared network stack) returns untouched (decision 24).
        ["-A", bridge_chain, *comment, "-j", "RETURN"],
    ])
    for protocol in ("tcp", "udp"):
        hooks.append(["-A", "OUTPUT", "-s", p["guest"] + "/32", "!", "-d", "127.0.0.0/8", "-p", protocol, *local, *fresh, *comment, "-j", chain])
        # Resolver traffic may carry WSL's synthetic source (10.255.255.254)
        # or another resolver-selected source. Only its recorded DNS tuple is
        # eligible, and its return address is always translated to this guest.
        dns = ["-p", protocol, "-m", protocol, "--dport", "53"]
        hooks.append(["-A", "OUTPUT", "-d", p["system_dns"] + "/32", *dns, *local, *fresh, *comment, "-j", chain])
        # Forwarded container traffic has no local cgroup socket, and every
        # standard distribution shares this network stack, so the rule alone
        # cannot tell whose bridge a packet came from. It only enters the
        # bridge chain; per-network rules there pick the target's own Docker
        # networks (decision 24). Redirected packets are SNATed back to the
        # guest address so the ingress can use the same reply tuple.
        hooks.append(["-A", "PREROUTING", "!", "-i", "eth0", "-p", protocol, "-m", protocol, *fresh, *comment, "-j", bridge_chain])
        hooks.append(["-A", "POSTROUTING", "-d", ingress + "/32", "-p", protocol, "-m", protocol, "--dport", str(ingress_port), "-m", "conntrack", "--ctdir", "ORIGINAL", "--ctstate", "DNAT", "-m", "connmark", "--mark", mark, *comment, "-j", "SNAT", "--to-source", p["guest"]])
    guards = [
        ["-A", "OUTPUT", *local, "-m", "conntrack", "!", "--ctorigdst", "127.0.0.0/8", *comment, "-j", guard_chain],
        ["-A", "OUTPUT", "!", "-d", "127.0.0.0/8", *local, "-m", "conntrack", "--ctstate", "INVALID,UNTRACKED", *comment, "-j", guard_chain],
        ["-A", guard_chain, "-m", "conntrack", "--ctdir", "REPLY", *comment, "-j", "RETURN"],
        # SOCKS5 has no ICMP mode, so ICMP and every other non-TCP/UDP protocol
        # falls through to the final DROP. A RETURN here would leave the guest
        # through Windows NAT and expose the host's own public address.
    ]
    guards.extend(forward_gate(forward_chain, forward_bridges, comment, mark, ingress + "/32"))
    for dns_only in (False, True):
        for protocol in ("tcp", "udp"):
            # In xt_conntrack DNAT is a virtual state, not a --ctstatus value.
            proof = ["-m", "conntrack", "--ctstate", "DNAT", "--ctdir", "ORIGINAL"]
            source = [] if dns_only else ["-s", p["guest"] + "/32"]
            if dns_only:
                proof += ["--ctorigdst", p["system_dns"], "--ctorigdstport", "53"]
            else:
                proof += ["--ctorigsrc", p["guest"]]
            established = ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "--ctdir", "ORIGINAL"]
            established += ["--ctorigdst", p["system_dns"], "--ctorigdstport", "53"] if dns_only else ["--ctorigsrc", p["guest"]]
            # Only this takeover's own flows carry its mark: one the target
            # opened before the takeover never leaves directly (decision 29).
            guards.append(["-A", guard_chain, *source, "-p", protocol, *established, "-m", "connmark", "--mark", mark, *comment, "-j", "RETURN"])
            guards.append(["-A", guard_chain, *source, "-d", ingress + "/32", "-p", protocol, "-m", protocol, "--dport", str(ingress_port), *proof, "-m", "connmark", "--mark", mark, *comment, "-j", "RETURN"])
    guards.extend(stale_flow_guards(guard_chain, comment))
    return chain, tag, hooks, body, guards


def stale_flow_guards(guard_chain, comment):
    """The end of a local guard chain. A TCP connection the target opened
    before this takeover gets a reset on its next packet, so the application
    notices at once and reconnects through the redirect; everything else
    left, old UDP flows included, is dropped (decision 29)."""
    return [
        ["-A", guard_chain, "-p", "tcp", "-m", "conntrack", "--ctstate", "ESTABLISHED", "--ctdir", "ORIGINAL", *comment, "-j", "REJECT", "--reject-with", "tcp-reset"],
        ["-A", guard_chain, *comment, "-j", "DROP"],
    ]


def ipv6_artifacts(p):
    require("ipv6" in p, "ipv6_plan_missing")
    guest, _ = endpoint6("[" + p["ipv6"]["guest"] + "]:1")
    ingress, ingress_port = endpoint6(p["ipv6"]["ingress"])
    cookie = f"{p['cookie']:08x}"
    chain, guard_chain = "WPM2V_" + cookie, "WPM2VG_" + cookie
    bridge_chain, forward_chain, forward_bridges = "WPM2VB_" + cookie, "WPM2VF_" + cookie, "WPM2VFB_" + cookie
    digest = plan_digest(p)[:16]
    tag = "wsl-proxyctl-m2v6:" + cookie + ":" + digest
    comment = ["-m", "comment", "--comment", tag]
    mark = f"0x{p['cookie']:x}"
    local = ["-m", "cgroup", "--path", "/"]
    fresh = ["-m", "conntrack", "--ctstate", "NEW", "--ctdir", "ORIGINAL"]
    hooks, body = [], []
    for protocol in ("tcp", "udp"):
        body.append(["-A", chain, "-d", ingress + "/128", "-p", protocol, "-m", protocol, "--dport", str(ingress_port), *comment, "-j", "RETURN"])
    for network in ("::/128", "::1/128", "::ffff:0:0/96", "fe80::/10", "ff00::/8"):
        body.append(["-A", chain, "-d", network, *comment, "-j", "RETURN"])
    body.extend([
        ["-A", chain, "-m", "connmark", "--mark", "0x0", *comment, "-j", "CONNMARK", "--set-xmark", mark + "/0xffffffff"],
        ["-A", chain, "-p", "tcp", "-m", "connmark", "--mark", mark, *comment, "-j", "DNAT", "--to-destination", f"[{ingress}]:{ingress_port}"],
        ["-A", chain, "-p", "udp", "-m", "connmark", "--mark", mark, *comment, "-j", "DNAT", "--to-destination", f"[{ingress}]:{ingress_port}"],
        ["-A", bridge_chain, *comment, "-j", "RETURN"],
    ])
    for protocol in ("tcp", "udp"):
        hooks.append(["-A", "OUTPUT", "-s", guest + "/128", "!", "-d", "::1/128", "-p", protocol, *local, *fresh, *comment, "-j", chain])
        hooks.append(["-A", "PREROUTING", "!", "-i", "eth0", "-p", protocol, "-m", protocol, *fresh, *comment, "-j", bridge_chain])
        hooks.append(["-A", "POSTROUTING", "-d", ingress + "/128", "-p", protocol, "-m", protocol, "--dport", str(ingress_port), "-m", "conntrack", "--ctdir", "ORIGINAL", "--ctstate", "DNAT", "-m", "connmark", "--mark", mark, *comment, "-j", "SNAT", "--to-source", guest])
    guards = [
        ["-A", "OUTPUT", *local, "-m", "conntrack", "!", "--ctorigdst", "::1/128", *comment, "-j", guard_chain],
        ["-A", "OUTPUT", "!", "-d", "::1/128", *local, "-m", "conntrack", "--ctstate", "INVALID,UNTRACKED", *comment, "-j", guard_chain],
        ["-A", guard_chain, "-m", "conntrack", "--ctdir", "REPLY", *comment, "-j", "RETURN"],
    ]
    for protocol in ("tcp", "udp"):
        guards.append(["-A", guard_chain, "-s", guest + "/128", "-p", protocol, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "--ctdir", "ORIGINAL", "--ctorigsrc", guest, "-m", "connmark", "--mark", mark, *comment, "-j", "RETURN"])
        guards.append(["-A", guard_chain, "-s", guest + "/128", "-d", ingress + "/128", "-p", protocol, "-m", protocol, "--dport", str(ingress_port), "-m", "conntrack", "--ctstate", "DNAT", "--ctdir", "ORIGINAL", "--ctorigsrc", guest, "-m", "connmark", "--mark", mark, *comment, "-j", "RETURN"])
    guards.extend(forward_gate(forward_chain, forward_bridges, comment, mark, ingress + "/128"))
    guards.extend(stale_flow_guards(guard_chain, comment))
    return chain, guard_chain, tag, hooks, body, guards


def ipv6_guards(p):
    if p.get("ipv6") is not None:
        return ipv6_artifacts(p)[5]
    if p.get("system_dns") is None:
        return []
    cookie = f"{p['cookie']:08x}"
    comment = ["-m", "comment", "--comment", artifacts(p)[1]]
    base = ["-A", "OUTPUT", "-m", "cgroup", "--path", "/"]
    # Without an IPv6 plan, drop local external traffic, and the forwarded
    # IPv6 of the target's own container networks (decision 24), so neither
    # can bypass the managed policy. Other bridges are left alone.
    return [
        [*base, "-m", "conntrack", "--ctdir", "ORIGINAL", "!", "--ctorigdst", "::1/128", *comment, "-j", "DROP"],
        [*base, "!", "-d", "::1/128", "-m", "conntrack", "--ctstate", "INVALID,UNTRACKED", *comment, "-j", "DROP"],
        *forward_gate("WPM2VF_" + cookie, "WPM2VFB_" + cookie, comment),
    ]


def block_tag(p, ipv6=False):
    return ("wsl-proxyctl-m2v6k:" if ipv6 else "wsl-proxyctl-m2k:") + f"{p['cookie']:08x}:" + plan_digest(p)[:16]


def block_rules(p, ipv6=False):
    """The drop-only rules a lost managed takeover leaves in the target
    (decision 33): everything the target's own processes start, except to
    loopback, is dropped, the same shape as IPv6 block mode. No redirection,
    no DNS. Replies to connections opened into the target still pass. The
    target's forwarded container traffic is not covered. Matched with
    `--path /` in whatever cgroup namespace the target runs in now, so they
    apply after a restart, when the takeover's own rules no longer do."""
    if p.get("system_dns") is None:
        return []
    loopback = "::1/128" if ipv6 else "127.0.0.0/8"
    comment = ["-m", "comment", "--comment", block_tag(p, ipv6)]
    base = ["-A", "OUTPUT", "-m", "cgroup", "--path", "/"]
    return [
        [*base, "-m", "conntrack", "--ctdir", "ORIGINAL", "!", "--ctorigdst", loopback, *comment, "-j", "DROP"],
        [*base, "!", "-d", loopback, "-m", "conntrack", "--ctstate", "INVALID,UNTRACKED", *comment, "-j", "DROP"],
    ]


def forward_gate(forward_chain, forward_bridges, comment, mark=None, ingress=None):
    """The FORWARD hook and its chains. Replies to connections opened from
    elsewhere pass; this instance's redirected flows are accepted; then the
    per-network rules for the target's own container bridges (in
    `forward_bridges`) drop what those containers send that was not
    redirected. Everything else returns untouched (decision 24)."""
    rules = [
        ["-A", "FORWARD", *comment, "-j", forward_chain],
        ["-A", forward_chain, "-m", "conntrack", "--ctdir", "REPLY", *comment, "-j", "RETURN"],
    ]
    if mark is not None:
        for protocol in ("tcp", "udp"):
            rules.append(["-A", forward_chain, "-p", protocol, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "connmark", "--mark", mark, *comment, "-j", "ACCEPT"])
            rules.append(["-A", forward_chain, "-d", ingress, "-p", protocol, "-m", "conntrack", "--ctstate", "DNAT", "--ctdir", "ORIGINAL", "-m", "connmark", "--mark", mark, *comment, "-j", "ACCEPT"])
    rules.extend([
        ["-A", forward_chain, *comment, "-j", forward_bridges],
        ["-A", forward_chain, *comment, "-j", "RETURN"],
        ["-A", forward_bridges, *comment, "-j", "RETURN"],
    ])
    return rules


def instance_chains(p, ipv6=False):
    """Every chain this instance owns in one address family, with its table,
    in creation order."""
    cookie = f"{p['cookie']:08x}"
    if p.get("system_dns") is None:
        return {} if ipv6 else {"WPM1_" + cookie: "nat"}
    if not ipv6:
        names = (("WPM2_", "nat"), ("WPM2B_", "nat"), ("WPM2G_", "filter"), ("WPM2F_", "filter"), ("WPM2FB_", "filter"))
    elif p.get("ipv6") is not None:
        names = (("WPM2V_", "nat"), ("WPM2VB_", "nat"), ("WPM2VG_", "filter"), ("WPM2VF_", "filter"), ("WPM2VFB_", "filter"))
    else:
        names = (("WPM2VF_", "filter"), ("WPM2VFB_", "filter"))
    return {prefix + cookie: table for prefix, table in names}


def all_instance_chains(cookie):
    """Chain names any mode of this instance could own; finding one where it
    does not belong is a collision."""
    prefixes = ("WPM1_", "WPM2_", "WPM2B_", "WPM2G_", "WPM2F_", "WPM2FB_", "WPM2V_", "WPM2VB_", "WPM2VG_", "WPM2VF_", "WPM2VFB_")
    return {prefix + cookie for prefix in prefixes}


def legacy_rules(p, ipv6=False):
    """Rules an older version installed for this plan: in place of today's
    bridge and FORWARD hooks, PREROUTING ! -i eth0 straight into the redirect
    chain, and accepts plus a global drop on FORWARD (decision 24); in the
    guard chain, accepts for established flows without this instance's mark
    (decision 29). Recognised only so that a stop can remove them; they
    never count as complete."""
    if p.get("system_dns") is None:
        return []
    return [*legacy_bridge_rules(p, ipv6), *legacy_guard_rules(p, ipv6)]


def legacy_guard_rules(p, ipv6=False):
    """Today's established-flow accepts of the local guard chain without the
    mark they now require."""
    if ipv6 and p.get("ipv6") is None:
        return []
    guards = ipv6_artifacts(p)[5] if ipv6 else artifacts(p)[4]
    mark = f"0x{p['cookie']:x}"
    unmarked = []
    for rule in guards:
        if rule[1].startswith(("WPM2G_", "WPM2VG_")) and "ESTABLISHED,RELATED" in rule:
            at = rule.index("connmark") - 1
            require(rule[at:at + 4] == ["-m", "connmark", "--mark", mark], "unexpected_guard_shape")
            unmarked.append(rule[:at] + rule[at + 4:])
    return unmarked


def legacy_bridge_rules(p, ipv6=False):
    mark = f"0x{p['cookie']:x}"
    fresh = ["-m", "conntrack", "--ctstate", "NEW", "--ctdir", "ORIGINAL"]
    if not ipv6:
        chain, tag = artifacts(p)[0], artifacts(p)[1]
        ingress = endpoint(p["ingress"])[0] + "/32"
    elif p.get("ipv6") is not None:
        chain, _, tag, _, _, _ = ipv6_artifacts(p)
        ingress = endpoint6(p["ipv6"]["ingress"])[0] + "/128"
    else:
        return [["-A", "FORWARD", "-m", "comment", "--comment", artifacts(p)[1], "-j", "DROP"]]
    comment = ["-m", "comment", "--comment", tag]
    rules = []
    for protocol in ("tcp", "udp"):
        rules.append(["-A", "PREROUTING", "!", "-i", "eth0", "-p", protocol, "-m", protocol, *fresh, *comment, "-j", chain])
        rules.append(["-A", "FORWARD", "-p", protocol, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "connmark", "--mark", mark, *comment, "-j", "RETURN"])
        rules.append(["-A", "FORWARD", "-d", ingress, "-p", protocol, "-m", "conntrack", "--ctstate", "DNAT", "--ctdir", "ORIGINAL", "-m", "connmark", "--mark", mark, *comment, "-j", "RETURN"])
    rules.append(["-A", "FORWARD", *comment, "-j", "DROP"])
    return rules



DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
BRIDGE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,15}")
# Destinations that cannot be routed off the host (multicast, limited
# broadcast, IPv6 link-local): the gate lets them through. Link-local IPv4
# (169.254.0.0/16, e.g. 169.254.169.254) is routable and stays dropped, as
# for the target's own processes.
LOCAL_SCOPES = {"v4": ("224.0.0.0/4", "255.255.255.255/32"), "v6": ("fe80::/10", "ff00::/8")}


def dockerd_running(proc="/proc", netns=None):
    """Whether a dockerd process runs in the target (its own PID namespace)
    and in this network stack. Only then is docker.sock asked: connecting to
    an idle socket-activated one would start Docker, and a socket without a
    daemon here may lead to another distribution's. A dockerd in a network
    namespace of its own (rootless Docker, Docker in a container) has no
    bridges here; its containers leave through processes in the target's
    cgroup and count as the target's own traffic (decision 24)."""
    netns = netns or (lambda pid: os.readlink(os.path.join(proc, pid, "ns", "net")))
    try:
        own = netns("self")
    except OSError:
        return False
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc, entry, "comm"), "rb") as handle:
                if handle.read(64).strip() == b"dockerd" and netns(entry) == own:
                    return True
        except OSError:
            continue
    return False


def docker_request(path, socket_path, timeout=3, limit=4 << 20):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect(socket_path)
        connection.sendall(b"GET " + path.encode("ascii") + b" HTTP/1.0\r\nHost: docker\r\n\r\n")
        data = b""
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            data += chunk
            require(len(data) <= limit, "docker_response_too_large")
    finally:
        connection.close()
    head, separator, body = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].split(b" ")
    require(bool(separator) and len(status) >= 2 and status[1] == b"200", "docker_request_failed")
    return json.loads(body)


def parse_docker_networks(networks, exists):
    """{bridge name: {"v4": [subnets], "v6": [subnets]}} for the bridge-driver
    networks whose interface `exists` in this network stack."""
    require(isinstance(networks, list), "docker_networks_invalid")
    result = {}
    for network in networks:
        if not isinstance(network, dict) or network.get("Driver") != "bridge":
            continue
        options = network.get("Options")
        name = options.get("com.docker.network.bridge.name") if isinstance(options, dict) else None
        if not name:
            ident = network.get("Id")
            if not (isinstance(ident, str) and re.fullmatch(r"[0-9a-f]{12,64}", ident)):
                continue
            name = "br-" + ident[:12]
        if not (isinstance(name, str) and BRIDGE_NAME.fullmatch(name)) or name in ("eth0", "lo") or not exists(name):
            continue
        families = {"v4": set(), "v6": set()}
        ipam = network.get("IPAM")
        configs = ipam.get("Config") if isinstance(ipam, dict) else None
        for config in configs if isinstance(configs, list) else []:
            subnet = config.get("Subnet") if isinstance(config, dict) else None
            try:
                value = ipaddress.ip_network(subnet, strict=False)
            except (TypeError, ValueError):
                continue
            families["v6" if value.version == 6 else "v4"].add(str(value))
        result[name] = {family: sorted(values) for family, values in families.items()}
    return result


def docker_networks():
    """The target's own Docker bridge networks (decision 24); None when no
    dockerd runs in the target, so they are not known right now."""
    if not dockerd_running():
        return None
    path = next((path for path in DOCKER_SOCKETS if os.path.exists(path)), None)
    require(path is not None, "docker_socket_missing")
    try:
        networks = docker_request("/networks", path)
    except (OSError, ValueError) as error:
        raise Failure("docker_networks_unavailable") from error
    return parse_docker_networks(networks, lambda name: os.path.isdir("/sys/class/net/" + name))


def network_tag(p, ipv6=False):
    return ("wsl-proxyctl-m2v6n:" if ipv6 else "wsl-proxyctl-m2n:") + f"{p['cookie']:08x}:" + plan_digest(p)[:16]


def network_rules(p, networks, ipv6=False):
    """Per-network rules for the target's own Docker bridges, as (nat, filter)
    in the order they must end up in their chains (decision 24): traffic
    within the network stays local, other traffic is redirected like the
    target's own, and what was not redirected is dropped at forwarding. The
    target's own processes may reach the network's subnet through its bridge
    (the host, `docker-proxy` behind a published port): such packets never
    leave the host, and anything a container sends on is again subject to
    the rules above. Not in IPv6 block mode, where the target's own IPv6 is
    dropped on OUTPUT itself."""
    cookie = f"{p['cookie']:08x}"
    comment = ["-m", "comment", "--comment", network_tag(p, ipv6)]
    family = "v6" if ipv6 else "v4"
    if not ipv6:
        redirect, bridge_chain, gate, guard = "WPM2_" + cookie, "WPM2B_" + cookie, "WPM2FB_" + cookie, "WPM2G_" + cookie
    elif p.get("ipv6") is not None:
        redirect, bridge_chain, gate, guard = "WPM2V_" + cookie, "WPM2VB_" + cookie, "WPM2VFB_" + cookie, "WPM2VG_" + cookie
    else:
        redirect, bridge_chain, gate, guard = None, None, "WPM2VFB_" + cookie, None
    nat, filtered = [], []
    for name in sorted(networks):
        subnets = networks[name][family]
        if redirect is not None:
            nat.extend(["-A", bridge_chain, "-i", name, "-d", subnet, *comment, "-j", "RETURN"] for subnet in subnets)
            nat.append(["-A", bridge_chain, "-i", name, *comment, "-j", redirect])
        filtered.extend(["-A", gate, "-i", name, "-d", subnet, *comment, "-j", "RETURN"] for subnet in [*subnets, *LOCAL_SCOPES[family]])
        filtered.append(["-A", gate, "-i", name, *comment, "-j", "DROP"])
        if guard is not None:
            filtered.extend(["-A", guard, "-o", name, "-d", subnet, *comment, "-j", "RETURN"] for subnet in subnets)
    return nat, filtered


def network_rule_owner(p, rule, ipv6=False):
    """The bridge a per-network rule of this instance belongs to, or None when
    `rule` is not exactly one of them."""
    if network_tag(p, ipv6) not in rule:
        return None
    names = [rule[index + 1] for index, token in enumerate(rule[:-1]) if token in ("-i", "-o")]
    if len(names) != 1:
        return None
    name = names[0]
    if not BRIDGE_NAME.fullmatch(name) or name in ("eth0", "lo"):
        return None
    family = "v6" if ipv6 else "v4"
    subnets = []
    if "-d" in rule:
        try:
            value = ipaddress.ip_network(rule[rule.index("-d") + 1], strict=False)
        except (ValueError, IndexError):
            return None
        if value.version != (6 if ipv6 else 4):
            return None
        if str(value) not in LOCAL_SCOPES[family]:
            subnets.append(str(value))
    nat, filtered = network_rules(p, {name: {"v4": subnets, "v6": subnets}}, ipv6)
    try:
        key = rule_key(rule)
    except Failure:
        return None
    return name if key in {rule_key(candidate) for candidate in nat + filtered} else None


def installed_networks(p, found, ipv6=False):
    """{bridge: [(table, rule)]} for this instance's per-network rules in `found`."""
    result = {}
    for table in ("nat", "filter"):
        for rule in found.get(table, []):
            name = network_rule_owner(p, rule, ipv6)
            if name is not None:
                result.setdefault(name, []).append((table, rule))
    return result


def installed_network_map(p, found, ipv6=False):
    """The networks this instance's per-network rules in `found` cover, in
    the shape `docker_networks` returns."""
    family = "v6" if ipv6 else "v4"
    result = {}
    for name, rules in installed_networks(p, found, ipv6).items():
        subnets = set()
        for _, rule in rules:
            if "-d" in rule:
                subnet = str(ipaddress.ip_network(rule[rule.index("-d") + 1], strict=False))
                if subnet not in LOCAL_SCOPES[family]:
                    subnets.add(subnet)
        result[name] = {"v4": [], "v6": [], family: sorted(subnets)}
    return result


def wanted_networks(p, rules, ipv6_rules, exists=lambda name: os.path.isdir("/sys/class/net/" + name)):
    """The networks the per-network rules should cover now. While no dockerd
    runs here (stopped, restarting, possibly with live-restore keeping its
    containers up), the networks already covered stay covered as long as
    their bridge exists; only a bridge that is gone loses its rules. Never
    lets a still-attached container fall back to a direct path."""
    networks = docker_networks()
    if networks is not None:
        return networks
    kept = {}
    for found, ipv6 in ((rules, False), (ipv6_rules or {}, True)):
        for name, families in installed_network_map(p, found, ipv6).items():
            if exists(name):
                entry = kept.setdefault(name, {"v4": [], "v6": []})
                entry["v6" if ipv6 else "v4"] = families["v6" if ipv6 else "v4"]
    return kept


def network_changes(p, found, wanted, ipv6=False):
    """Bridges whose per-network rules differ from what `wanted` asks for, as
    (removals, additions): lists of (table, rule)."""
    installed = installed_networks(p, found, ipv6)
    removals, additions = [], []
    for name in sorted(set(installed) | set(wanted)):
        nat, filtered = network_rules(p, {name: wanted[name]} if name in wanted else {}, ipv6)
        want = [("nat", rule) for rule in nat] + [("filter", rule) for rule in filtered]
        have = installed.get(name, [])
        if sorted((table, rule_key(rule)) for table, rule in want) != sorted((table, rule_key(rule)) for table, rule in have):
            removals.extend(have)
            additions.extend(want)
    return removals, additions


def network_report(p, rules, ipv6_rules):
    """For the periodic check: the bridges with rules now, and whether they
    match the target's Docker networks, without changing anything."""
    installed = sorted(set(installed_networks(p, rules)) | set(installed_networks(p, ipv6_rules or {}, ipv6=True)))
    try:
        wanted = wanted_networks(p, rules, ipv6_rules)
    except Failure as error:
        return {"installed": installed, "wanted": None, "in_sync": None, "error": str(error)}
    in_sync = not any(network_changes(p, rules, wanted)) and not any(network_changes(p, ipv6_rules or {}, wanted, ipv6=True))
    return {"installed": installed, "wanted": sorted(wanted), "in_sync": in_sync, "error": None}

def firewall(ipv6=False):
    output = run(["ip6tables-legacy-save" if ipv6 else "iptables-legacy-save"])
    tables, table = {}, None
    for line in output.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            require(table is None and line[1:] not in tables, "invalid_firewall_dump")
            table = line[1:]
            tables[table] = {"chains": {}, "rules": []}
        elif line == "COMMIT":
            require(table is not None, "invalid_firewall_dump")
            table = None
        else:
            require(table is not None, "invalid_firewall_dump")
            if line.startswith(":"):
                fields = line[1:].split()
                require(len(fields) == 3 and fields[0] not in tables[table]["chains"], "invalid_chain_dump")
                tables[table]["chains"][fields[0]] = fields[1]
            else:
                tokens = shlex.split(line)
                require(len(tokens) >= 3 and tokens[0] == "-A", "invalid_rule_dump")
                tables[table]["rules"].append(tokens)
    require(table is None, "incomplete_firewall_dump")
    return tables


def mark_mentions(rule, cookie):
    # Parse only mark operands, never foreign cgroup paths or extension shapes.
    options = ("--mark", "--set-mark", "--set-xmark", "--and-mark", "--or-mark", "--xor-mark")
    for index, token in enumerate(rule):
        if token not in options:
            continue
        require(index + 1 < len(rule), "unparseable_foreign_mark_rule")
        try:
            pieces = rule[index + 1].split("/")
            require(1 <= len(pieces) <= 2, "unparseable_foreign_mark_rule")
            value = int(pieces[0], 0)
            mask = int(pieces[1], 0) if len(pieces) == 2 else 0xffffffff
        except ValueError as error:
            raise Failure("unparseable_foreign_mark_rule") from error
        require(0 <= value <= 0xffffffff and 0 <= mask <= 0xffffffff, "unparseable_foreign_mark_rule")
        matches = (cookie & mask) == (value & mask)
        if token == "--mark" and index and rule[index - 1] == "!":
            matches = not matches
        if token in ("--and-mark", "--or-mark", "--xor-mark") or matches:
            return True
    return False


def rule_key(rule):
    # iptables-save reorders extension options and normalizes host masks. Only
    # this closed vocabulary is accepted for an owned rule; unknown options,
    # duplicate constraints and negation cannot broaden a deletion predicate.
    require(len(rule) >= 2 and rule[0] == "-A", "invalid_owned_rule")
    allowed = {"-s", "-d", "-i", "-o", "-p", "-m", "-j", "--dport", "--path", "--ctstate", "--ctdir", "--ctstatus", "--ctorigsrc", "--ctorigdst", "--ctorigdstport", "--mark", "--comment", "--set-xmark", "--to-destination", "--to-source", "--reject-with"}
    result, seen = [], set()
    index = 2
    while index < len(rule):
        negated = rule[index] == "!"
        if negated:
            index += 1
        require(index < len(rule), "invalid_owned_negation")
        option = rule[index]
        require(option in allowed and index + 1 < len(rule), "unknown_owned_rule_option")
        require(not negated or option in ("-s", "-d", "-i", "--ctorigsrc", "--ctorigdst"), "unsupported_owned_negation")
        require(option in ("-m", "-i") or option not in seen, "duplicate_owned_rule_option")
        seen.add(option)
        value = rule[index + 1]
        if option in ("-s", "-d", "--ctorigsrc", "--ctorigdst"):
            value = str(ipaddress.ip_network(value, strict=False))
        elif option in ("--ctstate", "--ctstatus"):
            value = ",".join(sorted(value.split(",")))
        elif option in ("--mark", "--set-xmark"):
            pieces = value.split("/")
            require(1 <= len(pieces) <= 2, "invalid_owned_mark")
            number = int(pieces[0], 0)
            mask = int(pieces[1], 0) if len(pieces) == 2 else 0xffffffff
            require(0 <= number <= 0xffffffff and 0 <= mask <= 0xffffffff, "invalid_owned_mark")
            value = f"{number:x}/{mask:x}"
        result.append(("!" + option if negated else option, value))
        index += 2
    return rule[1], tuple(sorted(result))


def inspect_firewall(p, tables, existing, ipv6=False):
    chain, tag, hooks, body, guards = artifacts(p)
    if ipv6 and p.get("ipv6") is not None:
        v6_chain, v6_guard, tag, hooks, body, guards = ipv6_artifacts(p)
        chain = v6_chain
    cookie = f"{p['cookie']:08x}"
    reserved = all_instance_chains(cookie)
    chains = instance_chains(p, ipv6)
    expected = {
        "nat": [rule_key(rule) for rule in hooks + body] if (not ipv6 or p.get("ipv6") is not None) else [],
        "filter": [rule_key(rule) for rule in (ipv6_guards(p) if ipv6 else guards)],
    }
    # An older version's hooks are this instance's too, for removal only;
    # `rules_complete` still compares against today's exact set.
    for rule in legacy_rules(p, ipv6):
        expected["nat" if rule[1] == "PREROUTING" else "filter"].append(rule_key(rule))
    # The drop-only rules of a lost takeover (decision 33): removed with the
    # rest, never part of a complete set, and they need none of the chains.
    blocking = block_tag(p, ipv6) if p.get("system_dns") is not None else None
    blocked = {rule_key(rule) for rule in block_rules(p, ipv6)}
    found = {"nat": [], "filter": []}
    seen = {"nat": set(), "filter": set()}
    observed_chains = set()
    present = False
    prefixes = tuple("wsl-proxyctl-" + mode + ":" + cookie + ":" for mode in ("m1", "m2", "m2v6", "m2n", "m2v6n", "m2k", "m2v6k"))
    for name, table in tables.items():
        for owned_chain in reserved.intersection(table["chains"]):
            require(existing and chains.get(owned_chain) == name and table["chains"][owned_chain] == "-", "instance_chain_collision")
            require(any(rule[1] == owned_chain for rule in table["rules"]), "unproven_empty_instance_chain")
            observed_chains.add(owned_chain)
            present |= owned_chain == chain
        for rule in table["rules"]:
            if blocking is not None and blocking in rule:
                key = rule_key(rule)
                require(name == "filter" and key in blocked, "foreign_instance_rule")
                require(existing, "instance_rule_collision")
                require(key not in seen[name], "duplicate_instance_rule")
                seen[name].add(key)
                found[name].append(rule)
                continue
            candidate = tag in rule or any(value in rule for value in reserved)
            if candidate:
                key = rule_key(rule)
                # Per-network rules vary with the target's Docker networks;
                # each must still be exactly one of their shapes, in its chain.
                require(
                    key in expected.get(name, [])
                    or (network_rule_owner(p, rule, ipv6) is not None and chains.get(rule[1]) == name),
                    "foreign_instance_rule",
                )
                require(existing, "instance_rule_collision")
                require(key not in seen[name], "duplicate_instance_rule")
                seen[name].add(key)
                found[name].append(rule)
                continue
            require(not any(token.startswith(prefixes) for token in rule), "foreign_instance_rule")
            require(not mark_mentions(rule, p["cookie"]), "instance_mark_rule_collision")
    guarded = [rule for rule in found["filter"] if blocking is None or blocking not in rule]
    if found["nat"]:
        require(present, "owned_chain_missing")
    if ipv6 and p.get("ipv6") is not None and guarded:
        require(v6_guard in observed_chains, "owned_ipv6_guard_chain_missing")
    if not ipv6 and p.get("system_dns") is not None and guarded:
        require("WPM2G_" + cookie in observed_chains, "owned_guard_chain_missing")
    return present, found


def foreign_legacy_rules(dumps, owned):
    """How many rules in the shared legacy tables are not this instance's:
    a hint that some distribution writes legacy iptables, and any legacy write
    from another distribution rebinds this instance's `--path /` rules to it
    (decision 37). Counts only; never a reason to refuse."""
    total = sum(len(table["rules"]) for tables in dumps if tables for table in tables.values())
    mine = sum(len(rules) for found in owned if found for rules in found.values())
    return max(total - mine, 0)


def rules_complete(p, present, rules, ipv6_rules):
    # Per-network rules come and go with the target's Docker networks and are
    # compared separately (`network_changes`).
    tags = (network_tag(p), network_tag(p, ipv6=True))
    same = lambda left, right: sorted(rule_key(rule) for rule in left if not any(tag in rule for tag in tags)) == sorted(rule_key(rule) for rule in right)
    if p.get("ipv6") is not None:
        _, _, hooks, body, guards = artifacts(p)
        _, _, _, v6_hooks, v6_body, v6_guards = ipv6_artifacts(p)
        return (
            present
            and ipv6_rules is not None
            and same(rules["nat"], hooks + body)
            and same(rules["filter"], guards)
            and same(ipv6_rules["nat"], v6_hooks + v6_body)
            and same(ipv6_rules["filter"], v6_guards)
        )
    _, _, hooks, body, guards = artifacts(p)
    return present and same(rules["nat"], hooks + body) and same(rules["filter"], guards) and (p.get("system_dns") is None or same(ipv6_rules["filter"], ipv6_guards(p)))


def transaction(table, lines, test=False, ipv6=False):
    arguments = ["ip6tables-legacy-restore" if ipv6 else "iptables-legacy-restore", "--wait", "2", "--noflush"]
    if test:
        arguments.append("--test")
    # This is xtables-restore input, not shell syntax: it treats shlex's single
    # quotes around `!` as data. All rules are typed/canonicalized before rendering.
    require(all(re.fullmatch(r"[A-Za-z0-9_:\[\]./%!,=+-]+", token) for line in lines for token in line), "unsafe_restore_token")
    document = "*" + table + "\n" + "\n".join(" ".join(line) for line in lines) + "\nCOMMIT\n"
    run(arguments, document)


# Reading the target's Docker networks at install: a few tries, so a dockerd
# whose API is not up yet right after the target booted is still covered from
# the first commit. Bounded well inside the 30 s guest deadline (3 s a read).
INSTALL_NETWORK_TRIES = 4
INSTALL_NETWORK_PAUSE = 1


def install_networks(p, pause=time.sleep):
    """The target's Docker networks to commit with the base rules (decision
    24), {} when no dockerd runs here, or None when a running dockerd still
    cannot be read: then only the base rules go in and the sync that follows
    reports the failure, as before."""
    if p.get("system_dns") is None:
        return {}
    for attempt in range(INSTALL_NETWORK_TRIES):
        try:
            return docker_networks() or {}
        except Failure:
            if attempt + 1 < INSTALL_NETWORK_TRIES:
                pause(INSTALL_NETWORK_PAUSE)
    return None


def install_rules(p, test=False, networks=None):
    """Commits this instance's rules. `networks` (managed mode only) adds the
    per-network rules to the same transactions, placed exactly where a
    following `sync_networks` would put them, so the target's containers are
    never forwarded unredirected between the two."""
    chain, _, hooks, body, guards = artifacts(p)
    insert = lambda rule: ["-I", rule[1], "1", *rule[2:]]
    builtin = ("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING")

    def lines(owned, table, rules):
        # Own chains first, then their contents in order, then the built-in
        # hooks in front of pre-existing rules. Each -I ... 1 reverses
        # insertion order, so the hooks go in backwards to keep their order.
        names = [name for name, kind in owned.items() if kind == table]
        return [
            *(["-N", name] for name in names),
            *(rule for rule in rules if rule[1] not in builtin),
            *(insert(rule) for rule in reversed([rule for rule in rules if rule[1] in builtin])),
        ]

    def with_networks(base, table, ipv6=False):
        # As in sync_networks: each -I ... 1 lands on top, so they go in
        # backwards to keep the subnet RETURNs ahead of their jump or drop.
        if not networks:
            return base
        nat, filtered = network_rules(p, networks, ipv6)
        return base + [insert(rule) for rule in reversed(nat if table == "nat" else filtered)]

    # Guards commit before redirection. An interrupted installation denies only
    # target workload traffic; the journal can recover either partial phase.
    if p.get("system_dns") is not None:
        transaction("filter", with_networks(lines(instance_chains(p), "filter", guards), "filter"), test)
        v6_owned = instance_chains(p, ipv6=True)
        if p.get("ipv6") is not None:
            _, _, _, v6_hooks, v6_body, v6_guards = ipv6_artifacts(p)
            # Like IPv4: the OUTPUT jumps go ahead of pre-existing accepts, or
            # ICMPv6 and other non-TCP/UDP packets could leave before the drop.
            transaction("filter", with_networks(lines(v6_owned, "filter", v6_guards), "filter", ipv6=True), test, ipv6=True)
            transaction("nat", with_networks(lines(v6_owned, "nat", v6_body + v6_hooks), "nat", ipv6=True), test, ipv6=True)
        else:
            transaction("filter", with_networks(lines(v6_owned, "filter", ipv6_guards(p)), "filter", ipv6=True), test, ipv6=True)
        # -N fails on a concurrent name collision; never flush an existing chain.
        transaction("nat", with_networks(lines(instance_chains(p), "nat", body + hooks), "nat"), test)
    else:
        transaction("filter", [insert(rule) for rule in guards], test)
        transaction("nat", lines(instance_chains(p), "nat", body + hooks), test)


# nfnetlink_conntrack UAPI. All CTA scalar payloads below are network-order;
# netlink headers and attribute lengths/types are native-endian.
NESTED = 0x8000
CT_NEW, CT_GET, CT_DELETE = 0, 1, 2
REQUEST, ACK, ROOT, MATCH = 1, 4, 0x100, 0x200
DUMP_INTR = 0x10
CTA_ORIG, CTA_REPLY, CTA_STATUS, CTA_MARK, CTA_ID, CTA_ZONE = 1, 2, 3, 8, 12, 18
NLA_HEADER = struct.Struct("=HH")


def attribute(kind, payload, nested=False):
    length = 4 + len(payload)
    return NLA_HEADER.pack(length, kind | (NESTED if nested else 0)) + payload + b"\0" * (-length % 4)


def attributes(payload):
    result = {}
    end = len(payload)
    offset = 0
    # This loop runs for every attribute in every fresh dump. Keep the bounds
    # checks inline, including the final check for missing alignment padding.
    while offset < end:
        remaining = end - offset
        if remaining < 4:
            raise Failure("short_netlink_attribute")
        length, kind = NLA_HEADER.unpack_from(payload, offset)
        if not 4 <= length <= remaining:
            raise Failure("invalid_netlink_attribute_length")
        kind &= 0x3fff
        if kind in result:
            raise Failure("duplicate_netlink_attribute")
        result[kind] = payload[offset + 4:offset + length]
        offset += (length + 3) & ~3
    if offset != end:
        raise Failure("truncated_netlink_attribute_padding")
    return result


def scalar(values, kind, width, default=None):
    if kind not in values:
        if default is None:
            raise Failure("missing_conntrack_attribute")
        return default
    value = values[kind]
    if len(value) != width:
        raise Failure("invalid_conntrack_scalar")
    return int.from_bytes(value, "big")


def parse_tuple(payload, ipv6=False):
    return parse_tuple_values(attributes(payload), ipv6)


def ipv6_text(value):
    rendered = str(ipaddress.IPv6Address(value))
    if "." not in rendered:
        return rendered
    prefix, dotted = rendered.rsplit(":", 1)
    octets = [int(part) for part in dotted.split(".")]
    mapped = f"{octets[0] << 8 | octets[1]:x}:{octets[2] << 8 | octets[3]:x}"
    return prefix + mapped if prefix.endswith(":") else prefix + ":" + mapped


def parse_tuple_values(values, ipv6=False):
    require(1 in values and 2 in values, "missing_conntrack_tuple")
    addresses, protocol = attributes(values[1]), attributes(values[2])
    number = scalar(protocol, 1, 1)
    if number not in (6, 17):
        return None
    source, destination, width = (3, 4, 16) if ipv6 else (1, 2, 4)
    require(source in addresses and destination in addresses and len(addresses[source]) == width and len(addresses[destination]) == width, "invalid_conntrack_tuple_address")
    return (
        number,
        ipv6_text(addresses[source]) if ipv6 else socket.inet_ntop(socket.AF_INET, addresses[source]),
        scalar(protocol, 2, 2),
        ipv6_text(addresses[destination]) if ipv6 else socket.inet_ntop(socket.AF_INET, addresses[destination]),
        scalar(protocol, 3, 2),
    )


def encode_tuple(value, ipv6=False):
    protocol, source, sport, destination, dport = value
    if ipv6:
        addresses = attribute(3, ipaddress.IPv6Address(source).packed) + attribute(4, ipaddress.IPv6Address(destination).packed)
    else:
        addresses = attribute(1, socket.inet_aton(source)) + attribute(2, socket.inet_aton(destination))
    transport = attribute(1, bytes([protocol])) + attribute(2, struct.pack("!H", sport)) + attribute(3, struct.pack("!H", dport))
    return attribute(1, addresses, True) + attribute(2, transport, True)


def parse_entry(payload):
    require(len(payload) >= 4 and payload[0] in (socket.AF_INET, socket.AF_INET6) and payload[1:4] == b"\x00\x00\x00", "invalid_conntrack_family")
    ipv6 = payload[0] == socket.AF_INET6
    values = attributes(payload[4:])
    require(CTA_ORIG in values and CTA_REPLY in values, "missing_conntrack_directions")
    original_values = attributes(values[CTA_ORIG])
    original = parse_tuple_values(original_values, ipv6)
    reply_values = attributes(values[CTA_REPLY])
    reply = parse_tuple_values(reply_values, ipv6)
    return {
        "original": original,
        "reply": reply,
        "mark": scalar(values, CTA_MARK, 4, 0),
        # CTA_ID is an opaque four-byte kernel ID: decoding and re-encoding
        # in the same order preserves it, including on little-endian guests.
        "id": scalar(values, CTA_ID, 4),
        "zone": scalar(values, CTA_ZONE, 2, 0),
        "tuple_zones": (scalar(original_values, 3, 2, 0), scalar(reply_values, 3, 2, 0)),
        "status": scalar(values, CTA_STATUS, 4),
    }


class Conntrack:
    def __init__(self):
        self.socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
        self.socket.bind((0, 0))
        self.socket.settimeout(2)
        self.pid = self.socket.getsockname()[0]
        self.sequence = 0
        self.begin()

    def begin(self):
        # Reuse one authenticated netlink socket for the lifetime of the
        # long-lived query helper. The deadline is per kernel operation, not
        # per helper process.
        self.deadline = time.monotonic() + 8

    def close(self):
        self.socket.close()

    def request(self, command, flags, payload=b"", ipv6=False):
        require(time.monotonic() < self.deadline, "conntrack_deadline")
        self.sequence += 1
        sequence = self.sequence
        body = bytes([socket.AF_INET6 if ipv6 else socket.AF_INET, 0, 0, 0]) + payload
        header = struct.pack("=IHHII", 16 + len(body), (1 << 8) | command, REQUEST | flags, sequence, self.pid)
        self.socket.sendto(header + body, (0, 0))
        messages, total = [], 0
        while True:
            require(time.monotonic() < self.deadline, "conntrack_deadline")
            packet, _, receive_flags, sender = self.socket.recvmsg(1024 * 1024)
            require(sender == (0, 0) and not receive_flags & socket.MSG_TRUNC, "untrusted_or_truncated_netlink_message")
            total += len(packet)
            require(total <= 16 * 1024 * 1024, "conntrack_dump_limit")
            offset = 0
            while offset < len(packet):
                require(len(packet) - offset >= 16, "short_netlink_header")
                length, kind, reply_flags, seq, pid = struct.unpack_from("=IHHII", packet, offset)
                require(16 <= length <= len(packet) - offset and seq == sequence and pid == self.pid, "invalid_netlink_envelope")
                require(not reply_flags & DUMP_INTR, "conntrack_dump_interrupted")
                data = packet[offset + 16:offset + length]
                offset += (length + 3) & ~3
                if kind == 2:
                    require(len(data) >= 4, "short_netlink_error")
                    error = struct.unpack_from("=i", data)[0]
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    require(flags & ACK and offset == len(packet), "unexpected_netlink_ack")
                    return messages
                if kind == 3:
                    require(flags & ROOT and len(data) >= 4 and struct.unpack_from("=i", data)[0] == 0 and offset == len(packet), "failed_conntrack_dump")
                    return messages
                require(kind == (1 << 8) | CT_NEW, "unexpected_netlink_message")
                messages.append(data)
            require(offset == len(packet), "truncated_netlink_padding")

    def dump(self, ipv6=False):
        return [parse_entry(payload) for payload in self.request(CT_GET, ROOT | MATCH, ipv6=ipv6)]

    def delete(self, entry, ipv6=False):
        require(integer(entry["id"], 0, 0xffffffff) and integer(entry["mark"], 1, 0xffffffff) and entry["zone"] == 0 and entry["tuple_zones"] == (0, 0), "unproven_delete_identity")
        original = attribute(CTA_ORIG, encode_tuple(entry["original"], ipv6), True)
        try:
            replies = self.request(CT_GET, ACK, original, ipv6=ipv6)
        except OSError as error:
            if error.errno == errno.ENOENT:
                return
            raise
        require(len(replies) == 1, "ambiguous_delete_revalidation")
        current = parse_entry(replies[0])
        if current["id"] != entry["id"]:
            return  # The original tuple expired and has already been reused.
        require(all(current[key] == entry[key] for key in ("original", "reply", "mark", "zone", "tuple_zones")), "mapping_ownership_changed_before_delete")
        # The kernel enforces original tuple + ID. Its delete operation does
        # not compare the reply tuple or mark, so revalidate those explicitly.
        payload = original + attribute(CTA_REPLY, encode_tuple(entry["reply"], ipv6), True)
        payload += attribute(CTA_ID, struct.pack("!I", entry["id"]))
        payload += attribute(CTA_MARK, struct.pack("!I", entry["mark"]))
        # Omission selects the proven default zone without requiring optional
        # kernel support for an explicit CTA_ZONE attribute containing zero.
        try:
            self.request(CT_DELETE, ACK, payload, ipv6=ipv6)
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise


_REAL_CONNTRACK = Conntrack
_CONNTRACK = None


def acquire_conntrack():
    global _CONNTRACK
    # Tests and diagnostic callers may replace Conntrack with a fake. Keep
    # those instances request-local so one fake cannot leak between cases.
    if Conntrack is not _REAL_CONNTRACK:
        return Conntrack(), False
    if _CONNTRACK is None:
        _CONNTRACK = Conntrack()
    else:
        _CONNTRACK.begin()
    return _CONNTRACK, True


def discard_conntrack(connection):
    global _CONNTRACK
    if _CONNTRACK is connection:
        try:
            connection.close()
        finally:
            _CONNTRACK = None


def authorized_origin(p, value):
    address, port = endpoint(value)
    if p.get("system_dns") is None:
        return value in p["origins"]
    return not p["origins"] and (address, port) != endpoint(p["ingress"])


class Ownership:
    def __init__(self, p):
        self.cookie = p["cookie"]
        self.guest = p["guest"]
        self.ingress = endpoint(p["ingress"])
        self.dns = p.get("system_dns")
        self.origins = frozenset(p["origins"])
        # Only immutable plan predicates survive between fresh dumps. Managed
        # bridge traffic is SNATed to the guest before it reaches Windows, so
        # its original conntrack source may be a private container address.

    def owned(self, entry, authorized=None):
        original, reply = entry["original"], entry["reply"]
        if original is None or reply is None:
            return False
        dns = self.dns is not None and (original[3], original[4]) == (self.dns, 53)
        if not (
            entry["mark"] == self.cookie
            and entry["zone"] == 0
            and entry["tuple_zones"] == (0, 0)
            and entry["status"] & 0x128 == 0x128  # CONFIRMED, DST_NAT, DST_NAT_DONE
            and original[0] == reply[0]
            and integer(entry["id"], 0, 0xffffffff)
            and original[0] in (6, 17)
            and (
                original[1] == self.guest
                or (
                    self.dns is not None
                    and (
                        (original[3] == self.dns and original[4] == 53)
                        or (
                            original[3] != self.dns
                            and original[4] != 53
                            and unicast(original[1])
                        )
                    )
                    and entry["status"] & 0x90 == 0x90
                )
            )
            and 1 <= original[2] <= 65535
            and (reply[1], reply[2]) == self.ingress
            and reply[3] == self.guest
            and 1 <= reply[4] <= 65535
        ):
            return False
        origin = f"{original[3]}:{original[4]}"
        if authorized is None:
            authorized = {}
        if origin not in authorized:
            try:
                destination = endpoint(origin)
                authorized[origin] = origin in self.origins if self.dns is None else not self.origins and destination != self.ingress
            except Failure:
                authorized[origin] = False
        return authorized[origin]

    def entries(self, entries):
        result, originals, replies, authorized = [], set(), set(), {}
        for entry in entries:
            if entry["mark"] == self.cookie:
                require(self.owned(entry, authorized), "instance_mark_has_unproven_mapping")
                original, reply = entry["original"], entry["reply"]
                require(original not in originals and reply not in replies, "duplicate_conntrack_mapping")
                originals.add(original)
                replies.add(reply)
                result.append(entry)
        return result


def owned(p, entry):
    return Ownership(p).owned(entry)


def owned_entries(p, entries):
    return Ownership(p).entries(entries)


class Ownership6:
    def __init__(self, p):
        ipv6 = p["ipv6"]
        self.cookie = p["cookie"]
        self.guest, _ = endpoint6("[" + ipv6["guest"] + "]:1")
        self.ingress = endpoint6(ipv6["ingress"])

    def owned(self, entry):
        original, reply = entry["original"], entry["reply"]
        if original is None or reply is None:
            return False
        return (
            entry["mark"] == self.cookie
            and entry["zone"] == 0
            and entry["tuple_zones"] == (0, 0)
            and entry["status"] & 0x128 == 0x128
            and original[0] == reply[0]
            and original[0] in (6, 17)
            and (
                original[1] == self.guest
                or (unicast6(original[1]) and entry["status"] & 0x90 == 0x90)
            )
            and (reply[1], reply[2]) == self.ingress
            and reply[3] == self.guest
            and 1 <= original[2] <= 65535
            and 1 <= reply[4] <= 65535
        )

    def entries(self, entries):
        result, originals, replies = [], set(), set()
        for entry in entries:
            if entry["mark"] == self.cookie:
                require(self.owned(entry), "instance_ipv6_mark_has_unproven_mapping")
                original, reply = entry["original"], entry["reply"]
                require(original not in originals and reply not in replies, "duplicate_ipv6_conntrack_mapping")
                originals.add(original)
                replies.add(reply)
                result.append(entry)
        return result


def unicast6(value):
    try:
        address = ipaddress.IPv6Address(value)
    except (ValueError, TypeError):
        return False
    return (
        not address.is_unspecified
        and not address.is_loopback
        and not address.is_multicast
        and address.ipv4_mapped is None
    )


def resolve6(p, entries, protocol, peer):
    origin = resolve6_optional(p, entries, protocol, peer)
    require(origin is not None, "mapping_missing_ambiguous_or_unowned")
    return origin


def resolve6_optional(p, entries, protocol, peer):
    prepared = Ownership6(p)
    entries = prepared.entries(entries)
    return resolve6_prepared(prepared, entries, protocol, peer)


def resolve6_prepared(prepared, entries, protocol, peer):
    _, port = endpoint6(peer)
    number = 6 if protocol == "tcp" else 17
    candidate = None
    for entry in entries:
        reply = entry["reply"]
        if reply == (number, prepared.ingress[0], prepared.ingress[1], prepared.guest, port):
            if candidate is not None:
                raise Failure("mapping_missing_ambiguous_or_unowned")
            candidate = entry
    if candidate is None:
        return None
    original = candidate["original"]
    return f"[{original[3]}]:{original[4]}"


def resolve6_queries(p, entries, queries):
    prepared = Ownership6(p)
    entries = prepared.entries(entries)
    return [resolve6_prepared(prepared, entries, protocol, peer) for protocol, peer in queries]


def exact_entry(ct, reply, ipv6=False):
    # A fresh kernel lookup of the one default-zone entry whose reply tuple is
    # what Windows actually received (ingress -> guest:port). The kernel keeps
    # reply tuples unique within a zone, so this costs a hash lookup instead of
    # a walk over every bucket and a decode of every entry in the shared table.
    # Other zones are not consulted; ownership already requires zone 0.
    payload = attribute(CTA_REPLY, encode_tuple(reply, ipv6), True)
    try:
        replies = ct.request(CT_GET, ACK, payload, ipv6=ipv6)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return None
        raise
    require(len(replies) == 1, "ambiguous_exact_conntrack_lookup")
    entry = parse_entry(replies[0])
    return entry if entry["reply"] == reply else None


def exact_queries(prepared, ct, queries):
    # No snapshot, index or result survives this call. Each answer is the
    # kernel's current entry for that tuple, checked with the full ownership
    # predicate; anything missing, foreign or malformed resolves to None.
    origins = []
    for protocol, peer in queries:
        require(protocol in ("tcp", "udp"), "invalid_lookup_protocol")
        address, port = endpoint(peer)
        require(address == prepared.guest, "invalid_lookup_peer")
        number = 6 if protocol == "tcp" else 17
        entry = exact_entry(ct, (number, *prepared.ingress, address, port))
        if entry is None or not prepared.owned(entry):
            origins.append(None)
            continue
        original = entry["original"]
        origins.append(f"{original[3]}:{original[4]}")
    return origins


def exact6_queries(p, ct, queries):
    prepared = Ownership6(p)
    origins = []
    for protocol, peer in queries:
        require(protocol in ("tcp", "udp"), "invalid_lookup_protocol")
        address, port = endpoint6(peer)
        require(address == prepared.guest, "invalid_lookup_peer")
        number = 6 if protocol == "tcp" else 17
        entry = exact_entry(ct, (number, prepared.ingress[0], prepared.ingress[1], prepared.guest, port), ipv6=True)
        if entry is None or not prepared.owned(entry):
            origins.append(None)
            continue
        original = entry["original"]
        origins.append(f"[{original[3]}]:{original[4]}")
    return origins


def inspect_mappings(p, ct):
    entries = owned_entries(p, ct.dump())
    if p.get("system_dns") is not None and p.get("ipv6") is None:
        # M2 never creates IPv6 NAT. A matching IPv6 connmark is foreign, not
        # permission to delete anything in the shared conntrack namespace.
        require(not any(entry["mark"] == p["cookie"] for entry in ct.dump(ipv6=True)), "instance_ipv6_connmark_collision")
    return entries


def inspect_ipv6_mappings(p, ct):
    if p.get("ipv6") is None:
        return []
    return Ownership6(p).entries(ct.dump(ipv6=True))


def partition_marked(cookie, entries, owned):
    """The entries carrying this instance's mark, split into provable mappings
    and a count of the rest. Unlike `Ownership.entries` it never fails: an
    entry that cannot be proven, or that shares a tuple with another marked
    entry, is only counted and never offered for deletion (decision 20)."""
    marked = [entry for entry in entries if entry["mark"] == cookie]
    originals, replies = {}, {}
    for entry in marked:
        originals[entry["original"]] = originals.get(entry["original"], 0) + 1
        replies[entry["reply"]] = replies.get(entry["reply"], 0) + 1
    proven = [
        entry
        for entry in marked
        if originals[entry["original"]] == 1 and replies[entry["reply"]] == 1 and owned(entry)
    ]
    return proven, len(marked) - len(proven)


def mapping_partition(p, ct):
    """For stop and inspection: (provable IPv4 mappings, provable IPv6
    mappings, count of marked entries that cannot be proven). Stopping
    deletes only the first two and still removes every exact-tagged rule."""
    ownership, authorized = Ownership(p), {}
    entries, unproven = partition_marked(p["cookie"], ct.dump(), lambda entry: ownership.owned(entry, authorized))
    ipv6_entries = []
    if p.get("ipv6") is not None:
        ipv6_entries, more = partition_marked(p["cookie"], ct.dump(ipv6=True), Ownership6(p).owned)
        unproven += more
    elif p.get("system_dns") is not None:
        # M2 without managed IPv6 never creates IPv6 NAT: a matching IPv6
        # connmark is not ours to delete.
        unproven += sum(1 for entry in ct.dump(ipv6=True) if entry["mark"] == p["cookie"])
    return entries, ipv6_entries, unproven


class MappingIndex:
    def __init__(self, prepared, entries):
        prepared.entries(entries)
        self.cookie = prepared.cookie
        self.guest = prepared.guest
        self.ingress = prepared.ingress
        self.replies = {}
        for entry in entries:
            reply = entry["reply"]
            if reply is not None:
                # Include foreign marks and every zone: either can make an
                # otherwise owned transport candidate ambiguous.
                self.replies[reply] = None if reply in self.replies else entry

    def resolve(self, protocol, peer):
        require(protocol in ("tcp", "udp"), "invalid_lookup_protocol")
        address, port = endpoint(peer)
        require(address == self.guest, "invalid_lookup_peer")
        number = 6 if protocol == "tcp" else 17
        candidate = self.replies.get((number, *self.ingress, address, port))
        if candidate is None or candidate["mark"] != self.cookie:
            return None
        original = candidate["original"]
        return f"{original[3]}:{original[4]}"


def prepare_lookup(p):
    validate({"operation": "precheck", "plan": p, "protocol": None, "peer": None})
    return Ownership(p)


def resolve_queries(prepared, entries, queries):
    # Neither the index nor destination-predicate memoization survives this
    # snapshot. Foreign marks/zones are included in transport ambiguity checks.
    index = MappingIndex(prepared, entries)
    return [index.resolve(protocol, peer) for protocol, peer in queries]


def resolve(p, entries, protocol, peer):
    origin = resolve_queries(prepare_lookup(p), entries, [(protocol, peer)])[0]
    require(origin is not None, "mapping_missing_ambiguous_or_unowned")
    return origin


def execute(request):
    p = validate(request)
    operation = request["operation"]
    with guest_lock():
        identity_matches = True
        drift = None
        unproven_left = None
        try:
            guard(p, check_resolver=operation not in ("remove", "inspect"), write_tools=operation != "inspect")
        except Failure as error:
            if operation not in ("inspect", "remove", "block"):
                raise
            # After any identity or environment drift (restart, rename, new
            # addresses, a workload outside the cgroup, ...), only inspect and
            # remove continue: inspect may attest absence only, and remove
            # deletes this instance's exact tagged firewall and conntrack
            # artifacts below. Every other operation fails. The reason is
            # returned so the host can tell a restart from a passing race.
            identity_matches = False
            drift = str(error)
        if operation == "arm":
            grant(p, "arm", request["deadline"])
            return {"ok": True, "operation": operation}
        if operation == "install":
            grant(p, "consume")
        elif operation == "remove":
            grant(p, "revoke")
        ct, cached_conntrack = acquire_conntrack()
        try:
            if operation in ("precheck", "install"):
                dumps = [firewall()]
                inspect_firewall(p, dumps[0], False)
                if p.get("system_dns") is not None or p.get("ipv6") is not None:
                    dumps.append(firewall(ipv6=True))
                    inspect_firewall(p, dumps[1], False, ipv6=True)
                require(not inspect_mappings(p, ct), "instance_connmark_collision")
                require(not inspect_ipv6_mappings(p, ct), "instance_ipv6_connmark_collision")
                # Read before anything commits, so the retries never sit
                # between the guards and the redirection.
                networks = install_networks(p) if operation == "install" else None
                # --test checks extension support without committing any table.
                install_rules(p, test=True, networks=networks)
                if operation == "install":
                    install_rules(p, networks=networks)
                else:
                    # Windows and the WSL VM need not agree on wall-clock seconds.
                    # Issue and validate in the guest; RPC transit can only shorten the window.
                    return {"ok": True, "operation": operation, "grant_deadline": int(time.time()) + 30, "legacy_foreign_rules": foreign_legacy_rules(dumps, [])}
            elif operation in ("remove", "inspect"):
                tables = firewall()
                present, rules = inspect_firewall(p, tables, True)
                ipv6_tables, ipv6_rules = None, None
                if p.get("system_dns") is not None or p.get("ipv6") is not None:
                    ipv6_tables = firewall(ipv6=True)
                    _, ipv6_rules = inspect_firewall(p, ipv6_tables, True, ipv6=True)
                # Complete both families and every owned tuple before any delete.
                # Marked entries that cannot be proven are counted, never deleted,
                # and do not stop the exact-tagged rules from going (decision 20);
                # the periodic check still treats any of them as a protection loss.
                entries, ipv6_entries, unproven = mapping_partition(p, ct)
                if operation == "inspect":
                    ownership = {
                        "identity_matches": identity_matches,
                        "rules_present": present or any(rules.values()) or bool(ipv6_rules and any(ipv6_rules.values())),
                        "rules_complete": rules_complete(p, present, rules, ipv6_rules),
                        "mappings_present": bool(entries or ipv6_entries),
                        "unproven_mappings": unproven,
                    }
                    require(identity_matches or not (ownership["rules_present"] or ownership["mappings_present"]), "stale_identity_has_owned_artifacts: " + str(drift))
                    if not ownership["rules_present"] and not ownership["mappings_present"]:
                        require(not grant_pending(p), "install_grant_pending")
                    result = {"ok": True, "operation": operation, "ownership": ownership, "legacy_foreign_rules": foreign_legacy_rules([tables, ipv6_tables], [rules, ipv6_rules])}
                    if drift is not None:
                        result["identity_error"] = drift
                    if p.get("system_dns") is not None and identity_matches and ownership["rules_complete"]:
                        result["networks"] = network_report(p, rules, ipv6_rules)
                    return result
                def withdraw(table, found, observed, ipv6=False):
                    # Every owned rule, then every owned chain that exists
                    # (an older version may have created fewer chains).
                    names = [name for name, kind in instance_chains(p, ipv6).items() if kind == table and name in observed.get(table, {}).get("chains", {})]
                    lines = [["-D", *rule[1:]] for rule in found] + [["-X", name] for name in names]
                    if lines:
                        transaction(table, lines, ipv6=ipv6)

                withdraw("nat", rules["nat"], tables)
                withdraw("filter", rules["filter"], tables)
                if ipv6_rules is not None:
                    withdraw("nat", ipv6_rules["nat"], ipv6_tables, ipv6=True)
                    withdraw("filter", ipv6_rules["filter"], ipv6_tables, ipv6=True)
                # Table commits synchronize old readers before exact tuple cleanup.
                for _ in range(4):
                    entries, ipv6_entries, unproven = mapping_partition(p, ct)
                    if not entries and not ipv6_entries:
                        break
                    for entry in entries:
                        ct.delete(entry)
                    for entry in ipv6_entries:
                        ct.delete(entry, ipv6=True)
                else:
                    raise Failure("owned_conntrack_residual")
                inspect_firewall(p, firewall(), False)
                if p.get("system_dns") is not None or p.get("ipv6") is not None:
                    inspect_firewall(p, firewall(ipv6=True), False, ipv6=True)
                entries, ipv6_entries, unproven = mapping_partition(p, ct)
                require(not entries and not ipv6_entries, "owned_conntrack_residual")
                unproven_left = unproven
            elif operation == "block":
                # A lost managed takeover only (decision 33). Every time,
                # one transaction per family deletes whatever drop-only rules
                # are there and inserts them again: after a target-only
                # restart the old ones read the same but still match the
                # cgroup namespace that is gone, and `--path /` resolves
                # anew only when a rule goes in. A stop removes them.
                require(p.get("system_dns") is not None, "block_needs_managed_mode")
                for ipv6 in (False, True):
                    _, found = inspect_firewall(p, firewall(ipv6=ipv6), True, ipv6=ipv6)
                    old = [["-D", *rule[1:]] for rule in found["filter"] if block_tag(p, ipv6) in rule]
                    fresh = [["-I", rule[1], "1", *rule[2:]] for rule in reversed(block_rules(p, ipv6))]
                    transaction("filter", old + fresh, ipv6=ipv6)
                in_place = 0
                for ipv6 in (False, True):
                    _, found = inspect_firewall(p, firewall(ipv6=ipv6), True, ipv6=ipv6)
                    have = sorted(rule_key(rule) for rule in found["filter"] if block_tag(p, ipv6) in rule)
                    require(have == sorted(rule_key(rule) for rule in block_rules(p, ipv6)), "block_not_in_place")
                    in_place += len(have)
                return {"ok": True, "operation": operation, "blocked": {"rules": in_place}}
            elif operation == "sync_networks":
                # Only an active, complete takeover of this exact identity is
                # extended (the guard above refused any drift); after a stop
                # the base rules are gone and nothing can be added.
                require(p.get("system_dns") is not None, "networks_need_managed_mode")
                tables, ipv6_tables = firewall(), firewall(ipv6=True)
                present, rules = inspect_firewall(p, tables, True)
                _, ipv6_rules = inspect_firewall(p, ipv6_tables, True, ipv6=True)
                require(rules_complete(p, present, rules, ipv6_rules), "network_sync_without_complete_rules")
                wanted = wanted_networks(p, rules, ipv6_rules)
                changes = [(False, *network_changes(p, rules, wanted)), (True, *network_changes(p, ipv6_rules, wanted, ipv6=True))]
                # Redirection goes before the drops it relies on when removing,
                # and after them when adding, as for the base rules.
                for table in ("nat", "filter"):
                    for ipv6, removals, _ in changes:
                        lines = [["-D", *rule[1:]] for kind, rule in removals if kind == table]
                        if lines:
                            transaction(table, lines, ipv6=ipv6)
                for table in ("filter", "nat"):
                    for ipv6, _, additions in changes:
                        rules_here = [rule for kind, rule in additions if kind == table]
                        # Each -I ... 1 lands on top, so insert backwards to
                        # keep the subnet RETURNs ahead of their jump or drop.
                        lines = [["-I", rule[1], "1", *rule[2:]] for rule in reversed(rules_here)]
                        if lines:
                            transaction(table, lines, ipv6=ipv6)
                added, removed = set(), set()
                for ipv6, removals, additions in changes:
                    removed.update(network_rule_owner(p, rule, ipv6) for _, rule in removals)
                    added.update(network_rule_owner(p, rule, ipv6) for _, rule in additions)
                # A network whose subnets changed is re-added, not removed.
                return {"ok": True, "operation": operation, "synced": {"current": sorted(wanted), "added": sorted(added), "removed": sorted(removed - set(wanted))}}
            else:
                if isinstance(request["peer"], str) and request["peer"].startswith("["):
                    origin = resolve6(p, ct.dump(ipv6=True), request["protocol"], request["peer"])
                else:
                    origin = resolve(p, ct.dump(), request["protocol"], request["peer"])
                return {"ok": True, "operation": operation, "origin": origin}
            result = {"ok": True, "operation": operation}
            if drift is not None:
                result["identity_error"] = drift
            if unproven_left is not None:
                result["unproven_mappings"] = unproven_left
            return result
        except (OSError, Failure) as error:
            if cached_conntrack and (
                isinstance(error, OSError) or "conntrack_" in str(error)
            ):
                discard_conntrack(ct)
            raise
        finally:
            if not cached_conntrack:
                ct.close()


def main():
    try:
        request = json.loads(bytes.fromhex(REQUEST_HEX).decode("utf-8"))
        result = execute(request)
        print(json.dumps(result, separators=(",", ":")), flush=True)
    except (Failure, OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        print("kernel_operation_failed: " + str(error), file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
