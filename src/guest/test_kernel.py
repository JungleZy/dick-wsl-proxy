"""Pure guest-kernel boundary tests; no guest or network operation is performed."""

import copy
import ipaddress
import json
import os
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

if os.name == "nt":
    from test_windows_compat import WindowsPosixOS, prepare_import

    prepare_import()
import kernel

if os.name == "nt":
    WindowsPosixOS().install(kernel)

# The legacy tables hold nothing of this instance unless a test says so:
# only an older version wrote there (decision 37).
REAL_LEGACY_FIREWALL = kernel.legacy_firewall
kernel.legacy_firewall = lambda ipv6=False: {}
# The probe sends a packet and reads live counters; tests that need it patch
# `probe_counts` and `socket` themselves.
REAL_PROBE_BOUND = kernel.probe_bound
kernel.probe_bound = lambda p: True


def plan():
    return {
        "target": {
            "id": "{01234567-89ab-cdef-0123-456789abcdef}",
            "name": "registered ' ; $(name)",
            "base_path": "D:\\WSL\\ProxyLab\\Target",
            "version": 2,
        },
        "cgroup_ns": "cgroup:[4026534269]",
        "cgroup_root": "25:386884",
        "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
        "guest": "172.28.83.138",
        "ingress": "172.28.80.1:43771",
        "origins": ["172.28.80.1:43772", "172.28.83.138:43772"],
        "cookie": 0x12345678,
    }


def comprehensive_plan():
    p = plan()
    p.update(system_dns="10.255.255.254", origins=[])
    return p


def comprehensive_entry(destination="93.184.216.34", port=443, source=None):
    p = comprehensive_plan()
    value = entry()
    value["original"] = (17, source or p["guest"], 44000, destination, port)
    if source is not None:
        value["status"] |= 0x90  # SRC_NAT and SRC_NAT_DONE.
    return value


def request(p=None):
    return {"operation": "precheck", "plan": p or plan(), "protocol": None, "peer": None}


def entry(p=None, origin=0, peer=45000, identifier=1):
    p = p or plan()
    address, port = kernel.endpoint(p["origins"][origin])
    ingress, ingress_port = kernel.endpoint(p["ingress"])
    return {
        "original": (17, p["guest"], 44000, address, port),
        "reply": (17, ingress, ingress_port, p["guest"], peer),
        "mark": p["cookie"],
        "id": identifier,
        "zone": 0,
        "tuple_zones": (0, 0),
        "status": 0x188 | 0x20,
    }


def encoded_entry(value, include_id=True):
    result = b"\x02\x00\x00\x00"
    result += kernel.attribute(kernel.CTA_ORIG, kernel.encode_tuple(value["original"]), True)
    result += kernel.attribute(kernel.CTA_REPLY, kernel.encode_tuple(value["reply"]), True)
    result += kernel.attribute(kernel.CTA_MARK, struct.pack("!I", value["mark"]))
    result += kernel.attribute(kernel.CTA_STATUS, struct.pack("!I", value["status"]))
    if include_id:
        result += kernel.attribute(kernel.CTA_ID, struct.pack("!I", value["id"]))
    if value.get("zone"):
        result += kernel.attribute(kernel.CTA_ZONE, struct.pack("!H", value["zone"]))
    return result


def declare_chains(tables, p, ipv6=False):
    for name, table in kernel.instance_chains(p, ipv6).items():
        tables.setdefault(table, {"chains": {"OUTPUT": "ACCEPT"}, "rules": []})["chains"][name] = "-"
    return tables


def tables_of(p, ipv6=False, backend="nft"):
    """A parsed dump holding exactly this instance's base rules, laid out as
    the given backend keeps them."""
    if not ipv6:
        _, _, hooks, body, guards = kernel.artifacts(p)
    else:
        hooks, body, guards = [], [], kernel.ipv6_guards(p)
        if p.get("ipv6") is not None:
            _, _, _, hooks, body, guards = kernel.ipv6_artifacts(p)
    tables = {}
    if hooks + body:
        tables["nat"] = {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(hooks + body)}
    for table, rules in kernel.split_guards(guards, backend).items():
        tables[table] = {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(rules)}
    for name, table in kernel.instance_chains(p, ipv6, backend).items():
        tables.setdefault(table, {"chains": {"OUTPUT": "ACCEPT"}, "rules": []})["chains"][name] = "-"
    return tables


def snapshot(p=None):
    return tables_of(p or plan())


def ipv6_snapshot(p):
    return tables_of(p, ipv6=True)


def ipv6_full_snapshot(p):
    return tables_of(p, ipv6=True)


LEGACY_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "legacy_rules.json")


def legacy_plan(name):
    p = comprehensive_plan()
    if name.endswith("managed"):
        p["ipv6"] = {"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"}
    return p


def apply_removal(state, table, lines, test=False, ipv6=False, backend="nft"):
    """A removal as iptables would apply it to a parsed dump: -D must hit an
    existing rule, -X an empty chain nothing jumps to; nothing else allowed."""
    if test:
        return
    current = state["v6" if ipv6 else "v4"][table]
    for line in lines:
        if line[0] == "-D":
            current["rules"].remove(["-A", *line[1:]])
        elif line[0] == "-X":
            assert not any(rule[1] == line[1] or rule[-1] == line[1] for rule in current["rules"]), line
            del current["chains"][line[1]]
        else:
            raise AssertionError(line)


class ValidationTests(unittest.TestCase):
    def test_registered_metacharacters_are_data(self):
        self.assertEqual(kernel.validate(request())["target"]["name"], plan()["target"]["name"])
        for key, value in (("name", "bad\nname"), ("id", "{01234567-89ab-cdef-0123-456789abcdef};id"), ("version", True)):
            p = plan()
            p["target"][key] = value
            with self.subTest(key=key), self.assertRaises(kernel.Failure):
                kernel.validate(request(p))

    def test_identity_and_local_tuple_boundaries(self):
        changes = [
            ("cookie", 0), ("cookie", True), ("cookie", 0x100000000),
            ("cgroup_ns", "cgroup:[1];id"), ("cgroup_ns", "cgroup:[01]"),
            ("cgroup_root", "25:0"), ("cgroup_root", "25:18446744073709551616"),
            ("boot_id", "01234567-89ab-cdef-0123-456789abcdef\n"),
            ("guest", "127.0.0.1"), ("ingress", "172.28.80.1:53"),
            ("origins", []), ("origins", ["172.28.80.1:43772"] * 2),
            ("origins", ["172.28.80.2:43772"]),
            ("origins", ["172.28.80.1:43771"]),
            ("origins", ["172.28.80.1:53"]),
            ("origins", ["172.28.80.1:043772"]),
        ]
        for key, value in changes:
            p = plan()
            p[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(kernel.Failure):
                kernel.validate(request(p))

    def test_unknown_keys_and_forged_lookup_peer(self):
        value = request()
        value["extra"] = "ignored"
        with self.assertRaises(kernel.Failure):
            kernel.validate(value)
        value = request()
        value.update(operation="lookup", protocol="udp", peer="172.28.80.1:44000")
        with self.assertRaises(kernel.Failure):
            kernel.validate(value)
        value["peer"] = "172.28.83.138:44000"
        value["protocol"] = "UDP"
        with self.assertRaises(kernel.Failure):
            kernel.validate(value)

    def test_comprehensive_mode_and_resolver_are_explicit_and_fail_closed(self):
        p = comprehensive_plan()
        self.assertEqual(kernel.validate(request(p)), p)
        for key, value in (("origins", plan()["origins"]), ("system_dns", None), ("system_dns", "127.0.0.53"), ("system_dns", "::1"), ("system_dns", "169.254.1.1")):
            modified = copy.deepcopy(p)
            modified[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(kernel.Failure):
                kernel.validate(request(modified))

    def test_resolver_layout_accepts_only_one_matching_literal_ipv4(self):
        p = comprehensive_plan()
        kernel.resolver_layout(p, "# WSL generated\nnameserver 10.255.255.254\nsearch example.test\n")
        for content in ("", "nameserver ::1", "nameserver 127.0.0.53", "nameserver 1.1.1.1", "nameserver 10.255.255.254\nnameserver 1.1.1.1", "nameserver 10.255.255.254\nnameserver 10.255.255.254"):
            with self.subTest(content=content), self.assertRaises(kernel.Failure):
                kernel.resolver_layout(p, content)

    def test_incompatible_layout_refusal_precedes_any_mutation(self):
        with patch.object(kernel, "guest_lock"), patch.object(kernel, "guard", side_effect=kernel.Failure("unsupported_or_changed_resolver_layout")), patch.object(kernel, "transaction") as transact, patch.object(kernel, "Conntrack") as conntrack:
            with self.assertRaises(kernel.Failure):
                kernel.execute(request(comprehensive_plan()))
        transact.assert_not_called()
        conntrack.assert_not_called()


class ConntrackTests(unittest.TestCase):
    def test_ipv4_mapped_ipv6_endpoints_are_rejected(self):
        with self.assertRaises(kernel.Failure):
            kernel.endpoint6("[::ffff:192.0.2.1]:443")

    def test_ipv6_mapping_resolves_only_through_the_recorded_ingress(self):
        p = comprehensive_plan()
        p["ipv6"] = {
            "guest": "2001:db8:1::2",
            "ingress": "[fe80::1%2]:43771",
        }
        value = {
            "original": (17, "2001:db8:1::2", 44000, "2001:db8:2::9", 443),
            "reply": (17, "fe80::1", 43771, "2001:db8:1::2", 45000),
            "mark": p["cookie"],
            "id": 1,
            "zone": 0,
            "tuple_zones": (0, 0),
            "status": 0x188 | 0x20,
        }
        assert kernel.resolve6(p, [value], "udp", "[2001:db8:1::2%2]:45000") == "[2001:db8:2::9]:443"
        forged = copy.deepcopy(value)
        forged["reply"] = (17, "2001:db8::bad", 43771, "2001:db8:1::2", 45000)
        with self.assertRaises(kernel.Failure):
            kernel.resolve6(p, [forged], "udp", "[2001:db8:1::2]:45000")

    def test_ipv6_mapping_accepts_a_forwarded_source_only_after_snat(self):
        p = comprehensive_plan()
        p["ipv6"] = {
            "guest": "2001:db8:1::2",
            "ingress": "[fe80::1%2]:43771",
        }
        forwarded = {
            "original": (17, "fd00::10", 44000, "2001:db8:2::9", 443),
            "reply": (17, "fe80::1", 43771, "2001:db8:1::2", 45000),
            "mark": p["cookie"],
            "id": 1,
            "zone": 0,
            "tuple_zones": (0, 0),
            "status": 0x188 | 0x20 | 0x90,
        }
        self.assertEqual(
            kernel.resolve6(p, [forwarded], "udp", "[2001:db8:1::2]:45000"),
            "[2001:db8:2::9]:443",
        )
        unnat = copy.deepcopy(forwarded)
        unnat["status"] &= ~0x90
        with self.assertRaises(kernel.Failure):
            kernel.resolve6(p, [unnat], "udp", "[2001:db8:1::2]:45000")

    def test_nested_tuple_round_trip_and_opaque_id_bytes(self):
        value = entry(identifier=0x78563412)
        parsed = kernel.parse_entry(encoded_entry(value))
        self.assertEqual(parsed, value)
        self.assertEqual(struct.pack("!I", parsed["id"]), b"\x78\x56\x34\x12")
        with self.assertRaises(kernel.Failure):
            kernel.parse_entry(encoded_entry(value, include_id=False))

    def test_malformed_and_duplicate_attributes_fail_closed(self):
        for data in (
            b"\0", struct.pack("=HH", 3, 1), struct.pack("=HH", 8, 1),
            kernel.attribute(1, b"one") + kernel.attribute(1, b"two"),
            kernel.attribute(1, b"x")[:-1],  # Missing the last padding byte.
            kernel.attribute(1 | 0x4000, b"one") + kernel.attribute(1, b"two", nested=True),
        ):
            with self.subTest(data=data), self.assertRaises(kernel.Failure):
                kernel.attributes(data)
        # A short, zero-valued CTA_ZONE is not proof of the default zone.
        with self.assertRaises(kernel.Failure):
            kernel.parse_entry(encoded_entry(entry()) + kernel.attribute(kernel.CTA_ZONE, b"\0"))

    def test_unproven_mark_tuple_zone_and_status_are_not_owned(self):
        p = plan()
        base = entry()
        changes = [
            ("mark", 0), ("zone", 1), ("tuple_zones", (0, 7)),
            ("status", 0x108),
            ("original", (17, p["guest"], 44000, "172.28.80.2", 43772)),
            ("original", (17, p["guest"], 0, "172.28.80.1", 43772)),
            ("reply", (17, "172.28.80.1", 43772, p["guest"], 45000)),
            ("reply", (17, "172.28.80.1", 43771, "172.28.83.139", 45000)),
        ]
        for key, value in changes:
            modified = copy.deepcopy(base)
            modified[key] = value
            with self.subTest(key=key):
                self.assertFalse(kernel.owned(p, modified))
                if modified["mark"] == p["cookie"]:
                    with self.assertRaises(kernel.Failure):
                        kernel.owned_entries(p, [modified])

    def test_same_original_port_distinct_wire_tuples_recover_distinct_addresses(self):
        p = plan()
        first, second = entry(), entry(origin=1, peer=45001, identifier=2)
        self.assertEqual(first["original"][2], second["original"][2])
        self.assertEqual(kernel.resolve(p, [first, second], "udp", p["guest"] + ":45000"), p["origins"][0])
        self.assertEqual(kernel.resolve(p, [first, second], "udp", p["guest"] + ":45001"), p["origins"][1])

    def test_missing_ambiguous_and_direct_forged_packets_are_rejected(self):
        p = plan()
        first = entry()
        second = entry(origin=1, identifier=2)
        direct = entry(identifier=3)
        direct["mark"] = 0
        direct["original"] = (17, p["guest"], 45000, "172.28.80.1", 43771)
        direct["status"] = 0x188
        for values in ([], [first, second], [direct], [first, direct], [first, first]):
            with self.subTest(values=values), self.assertRaises(kernel.Failure):
                kernel.resolve(p, values, "udp", p["guest"] + ":45000")

    def test_delete_includes_both_tuples_mark_and_exact_id_in_default_zone(self):
        value = entry(identifier=0x78563412)
        ct = object.__new__(kernel.Conntrack)
        with patch.object(ct, "request", side_effect=[[encoded_entry(value)], []]) as send:
            ct.delete(value)
        command, flags, payload = send.call_args.args
        self.assertEqual((command, flags), (kernel.CT_DELETE, kernel.ACK))
        values = kernel.attributes(payload)
        self.assertEqual(kernel.parse_tuple(values[kernel.CTA_ORIG]), value["original"])
        self.assertEqual(kernel.parse_tuple(values[kernel.CTA_REPLY]), value["reply"])
        self.assertEqual(values[kernel.CTA_ID], b"\x78\x56\x34\x12")
        self.assertEqual(values[kernel.CTA_MARK], struct.pack("!I", plan()["cookie"]))
        self.assertNotIn(kernel.CTA_ZONE, values)
        self.assertEqual(send.call_args_list[0].args[0], kernel.CT_GET)

    def test_ipv6_delete_uses_ipv6_conntrack_family_and_tuples(self):
        value = {
            "original": (17, "2001:db8:1::2", 44000, "2001:db8:2::9", 443),
            "reply": (17, "fe80::1", 43771, "2001:db8:1::2", 45000),
            "mark": plan()["cookie"],
            "id": 0x78563412,
            "zone": 0,
            "tuple_zones": (0, 0),
            "status": 0x188 | 0x20,
        }
        payload = bytes([kernel.socket.AF_INET6, 0, 0, 0])
        payload += kernel.attribute(kernel.CTA_ORIG, kernel.encode_tuple(value["original"], True), True)
        payload += kernel.attribute(kernel.CTA_REPLY, kernel.encode_tuple(value["reply"], True), True)
        payload += kernel.attribute(kernel.CTA_MARK, struct.pack("!I", value["mark"]))
        payload += kernel.attribute(kernel.CTA_STATUS, struct.pack("!I", value["status"]))
        payload += kernel.attribute(kernel.CTA_ID, struct.pack("!I", value["id"]))
        ct = object.__new__(kernel.Conntrack)
        with patch.object(ct, "request", side_effect=[[payload], []]) as send:
            ct.delete(value, ipv6=True)
        self.assertTrue(send.call_args_list[0].kwargs["ipv6"])
        self.assertTrue(send.call_args_list[1].kwargs["ipv6"])
        delete_values = kernel.attributes(send.call_args_list[1].args[2])
        self.assertEqual(kernel.parse_tuple(delete_values[kernel.CTA_ORIG], ipv6=True), value["original"])

    def test_reused_tuple_and_changed_mark_are_not_deleted(self):
        value = entry()
        ct = object.__new__(kernel.Conntrack)
        reused = entry(identifier=2)
        with patch.object(ct, "request", return_value=[encoded_entry(reused)]) as send:
            ct.delete(value)
        self.assertEqual(send.call_count, 1)
        changed = copy.deepcopy(value)
        changed["mark"] += 1
        with patch.object(ct, "request", return_value=[encoded_entry(changed)]) as send:
            with self.assertRaises(kernel.Failure):
                ct.delete(value)
        self.assertEqual(send.call_count, 1)

    def test_comprehensive_origin_requires_recorded_nat_proof_not_direct_ingress(self):
        p = comprehensive_plan()
        value = comprehensive_entry()
        self.assertEqual(kernel.resolve(p, [value], "udp", p["guest"] + ":45000"), "93.184.216.34:443")
        forwarded = comprehensive_entry(source="172.17.0.2")
        self.assertEqual(
            kernel.resolve(p, [forwarded], "udp", p["guest"] + ":45000"),
            "93.184.216.34:443",
        )
        for destination, port in (("127.0.0.1", 443), ("169.254.1.1", 443), ("224.0.0.1", 443), kernel.endpoint(p["ingress"])):
            forged = comprehensive_entry(destination, port)
            with self.subTest(destination=destination), self.assertRaises(kernel.Failure):
                kernel.resolve(p, [forged], "udp", p["guest"] + ":45000")
        for key, modified in (("mark", 0), ("zone", 1), ("tuple_zones", (1, 0)), ("id", None), ("status", 0x108)):
            forged = copy.deepcopy(value)
            forged[key] = modified
            with self.subTest(key=key), self.assertRaises(kernel.Failure):
                kernel.resolve(p, [forged], "udp", p["guest"] + ":45000")

    def test_only_verified_resolver_dns_can_use_nonstandard_source(self):
        p = comprehensive_plan()
        for source in ("10.255.255.254", "192.0.2.88", "127.0.0.1"):
            dns = comprehensive_entry(p["system_dns"], 53, source)
            self.assertEqual(kernel.resolve(p, [dns], "udp", p["guest"] + ":45000"), p["system_dns"] + ":53")
            for original in ((17, source, 44000, p["system_dns"], 54), (17, source, 44000, "1.1.1.1", 53)):
                forged = copy.deepcopy(dns)
                forged["original"] = original
                self.assertFalse(kernel.owned(p, forged))
            dns["status"] &= ~0x90
            self.assertFalse(kernel.owned(p, dns))


class PreparedLookupTests(unittest.TestCase):
    def test_ordered_mixed_protocol_queries_share_one_snapshot(self):
        p = plan()
        udp = entry()
        tcp = entry(origin=1, identifier=2)
        tcp["original"] = (6, *tcp["original"][1:])
        tcp["reply"] = (6, *tcp["reply"][1:])
        prepared = kernel.prepare_lookup(p)
        peer = p["guest"] + ":45000"
        self.assertEqual(
            kernel.resolve_queries(prepared, [udp, tcp], [("tcp", peer), ("udp", peer), ("udp", p["guest"] + ":45001"), ("tcp", peer)]),
            [p["origins"][1], p["origins"][0], None, p["origins"][1]],
        )

    def test_foreign_marks_and_cross_zone_candidates_remain_ambiguous(self):
        p = plan()
        prepared = kernel.prepare_lookup(p)
        query = [("udp", p["guest"] + ":45000")]
        for zone, tuple_zones in ((0, (0, 0)), (9, (0, 0)), (0, (7, 0)), (0, (0, 7))):
            foreign = entry(identifier=2)
            foreign.update(mark=0, zone=zone, tuple_zones=tuple_zones)
            for values in ([foreign], [entry(), foreign], [foreign, entry()], [entry(), foreign, foreign]):
                with self.subTest(zone=zone, tuple_zones=tuple_zones, values=values):
                    self.assertEqual(kernel.resolve_queries(prepared, values, query), [None])

    def test_every_cookie_row_is_validated_before_any_query_result(self):
        p = plan()
        prepared = kernel.prepare_lookup(p)
        query = [("udp", p["guest"] + ":45000")]
        for key, value in (("zone", 1), ("tuple_zones", (0, 1)), ("status", 0), ("id", True), ("original", None)):
            unrelated = entry(origin=1, peer=45001, identifier=2)
            unrelated[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(kernel.Failure, "instance_mark_has_unproven_mapping"):
                kernel.resolve_queries(prepared, [entry(), unrelated], query)
        for duplicate in (entry(peer=45001, identifier=2), entry(origin=1, identifier=2)):
            with self.subTest(duplicate=duplicate), self.assertRaisesRegex(kernel.Failure, "duplicate_conntrack_mapping"):
                kernel.resolve_queries(prepared, [entry(), duplicate], [("tcp", p["guest"] + ":45002")])

    def test_reused_preparation_never_reuses_mapping_or_destination_cache(self):
        p = comprehensive_plan()
        prepared = kernel.prepare_lookup(p)
        query = [("udp", p["guest"] + ":45000")]
        first = comprehensive_entry()
        second = comprehensive_entry("1.1.1.1", 53)
        second["id"] += 1
        with patch.object(kernel, "endpoint", wraps=kernel.endpoint) as parse:
            self.assertEqual(kernel.resolve_queries(prepared, [first], query), ["93.184.216.34:443"])
            self.assertEqual(kernel.resolve_queries(prepared, [second], query), ["1.1.1.1:53"])
            self.assertEqual(kernel.resolve_queries(prepared, [], query), [None])
            self.assertEqual(kernel.resolve_queries(prepared, [first], query), ["93.184.216.34:443"])
        self.assertEqual(parse.call_count, 7)  # Four peers, three fresh destination proofs.
        self.assertEqual(set(vars(prepared)), {"cookie", "guest", "ingress", "dns", "origins"})

    def test_plan_and_query_validation_remain_strict(self):
        p = plan()
        invalid = copy.deepcopy(p)
        invalid["cookie"] = True
        with self.assertRaises(kernel.Failure):
            kernel.prepare_lookup(invalid)
        prepared = kernel.prepare_lookup(p)
        for protocol, peer in (("UDP", p["guest"] + ":45000"), ("udp", "172.28.80.1:45000"), ("udp", p["guest"] + ":045000")):
            with self.subTest(protocol=protocol, peer=peer), self.assertRaises(kernel.Failure):
                kernel.resolve_queries(prepared, [entry()], [(protocol, peer)])

    def test_duplicate_detection_and_destination_validation_are_linear(self):
        class CountingTuple(tuple):
            comparisons = 0
            __hash__ = tuple.__hash__

            def __eq__(self, other):
                CountingTuple.comparisons += 1
                return tuple.__eq__(self, other)

        p = plan()
        prepared = kernel.prepare_lookup(p)
        values = []
        for number in range(256):
            value = entry(peer=45000 + number, identifier=number)
            value["original"] = CountingTuple((17, p["guest"], 44000 + number, "172.28.80.1", 43772))
            value["reply"] = CountingTuple(value["reply"])
            values.append(value)
        with patch.object(kernel, "endpoint", wraps=kernel.endpoint) as parse:
            self.assertEqual(kernel.resolve_queries(prepared, values, [("udp", p["guest"] + ":45000")]), [p["origins"][0]])
        self.assertEqual(parse.call_count, 2)  # One shared destination and one query peer.
        self.assertLess(CountingTuple.comparisons, len(values) * 4)

    def test_unrelated_foreign_rows_do_not_reparse_plan_or_destination(self):
        p = plan()
        prepared = kernel.prepare_lookup(p)
        foreign = entry()
        foreign.update(mark=0, original=None)
        foreign["reply"] = (17, "192.0.2.1", 9999, p["guest"], 45000)
        with patch.object(kernel, "endpoint", wraps=kernel.endpoint) as parse:
            self.assertEqual(kernel.resolve_queries(prepared, [foreign] * 256, [("udp", p["guest"] + ":45000")]), [None])
        parse.assert_called_once_with(p["guest"] + ":45000")

    def test_tuple_attributes_are_decoded_once_and_ipv4_stays_canonical(self):
        value = entry()
        payload = encoded_entry(value)
        with patch.object(kernel, "attributes", wraps=kernel.attributes) as parse:
            self.assertEqual(kernel.parse_entry(payload), value)
        self.assertEqual(parse.call_count, 7)
        for source, destination in (("0.0.0.0", "255.255.255.255"), ("1.2.3.4", "192.0.2.255")):
            original = (17, source, 1, destination, 65535)
            self.assertEqual(kernel.parse_tuple(kernel.encode_tuple(original)), original)

    def test_comprehensive_origin_checks_remain_exact_for_each_fresh_snapshot(self):
        p = comprehensive_plan()
        prepared = kernel.prepare_lookup(p)
        query = [("udp", p["guest"] + ":45000")]
        for destination, port in (("0.0.0.0", 443), ("127.0.0.1", 443), ("169.254.1.1", 443), ("224.0.0.1", 443), ("255.255.255.255", 443), ("::1", 443), ("1.1.1.1", 0), kernel.endpoint(p["ingress"])):
            with self.subTest(destination=destination, port=port), self.assertRaisesRegex(kernel.Failure, "instance_mark_has_unproven_mapping"):
                kernel.resolve_queries(prepared, [comprehensive_entry(destination, port)], query)

    def test_ipv6_tuple_formatting_is_unchanged(self):
        addresses = kernel.attribute(3, bytes.fromhex("00000000000000000000ffffc0000201"))
        addresses += kernel.attribute(4, bytes.fromhex("20010db8000000000000000000000001"))
        transport = kernel.attribute(1, b"\x11")
        transport += kernel.attribute(2, struct.pack("!H", 44000))
        transport += kernel.attribute(3, struct.pack("!H", 53))
        payload = kernel.attribute(1, addresses, True) + kernel.attribute(2, transport, True)
        self.assertEqual(kernel.parse_tuple(payload, ipv6=True), (17, "::ffff:c000:201", 44000, "2001:db8::1", 53))

    def test_tuple_zone_attributes_are_not_hidden_by_parse_reuse(self):
        value = entry()
        payload = b"\x02\x00\x00\x00"
        original = kernel.encode_tuple(value["original"])
        original += kernel.attribute(3, struct.pack("!H", 7))
        payload += kernel.attribute(kernel.CTA_ORIG, original, True)
        payload += kernel.attribute(kernel.CTA_REPLY, kernel.encode_tuple(value["reply"]), True)
        for kind, field in ((kernel.CTA_MARK, "mark"), (kernel.CTA_STATUS, "status"), (kernel.CTA_ID, "id")):
            payload += kernel.attribute(kind, struct.pack("!I", value[field]))
        parsed = kernel.parse_entry(payload)
        self.assertEqual(parsed["tuple_zones"], (7, 0))
        with self.assertRaisesRegex(kernel.Failure, "instance_mark_has_unproven_mapping"):
            kernel.resolve_queries(kernel.prepare_lookup(plan()), [parsed], [("udp", plan()["guest"] + ":45000")])
        duplicate = kernel.attribute(kernel.CTA_ORIG, original + kernel.attribute(3, b"\0\0"), True)
        fields = kernel.attributes(payload[4:])
        malformed = b"\x02\x00\x00\x00" + duplicate
        malformed += b"".join(kernel.attribute(kind, data) for kind, data in fields.items() if kind != kernel.CTA_ORIG)
        with self.assertRaisesRegex(kernel.Failure, "duplicate_netlink_attribute"):
            kernel.parse_entry(malformed)


class ExactConntrack:
    """Answers exact reply-tuple GETs like the kernel: one entry or ENOENT."""

    def __init__(self, *values, extra=None):
        self.values = values
        self.extra = extra or []
        self.requests = []

    def request(self, command, flags, payload=b"", ipv6=False):
        self.requests.append((command, flags, payload, ipv6))
        assert command == kernel.CT_GET and flags == kernel.ACK
        for value in self.values:
            if payload == kernel.attribute(kernel.CTA_REPLY, kernel.encode_tuple(value["reply"]), True):
                return [encoded_entry(value), *self.extra]
        raise OSError(kernel.errno.ENOENT, "No such file or directory")


class ExactLookupTests(unittest.TestCase):
    def test_owned_entry_resolves_with_one_exact_request_per_query(self):
        p = plan()
        udp = entry()
        tcp = entry(origin=1, peer=45001, identifier=2)
        tcp["original"] = (6, *tcp["original"][1:])
        tcp["reply"] = (6, *tcp["reply"][1:])
        ct = ExactConntrack(udp, tcp)
        queries = [("udp", p["guest"] + ":45000"), ("tcp", p["guest"] + ":45001"), ("tcp", p["guest"] + ":45000")]
        self.assertEqual(
            kernel.exact_queries(kernel.prepare_lookup(p), ct, queries),
            [p["origins"][0], p["origins"][1], None],
        )
        self.assertEqual(len(ct.requests), 3)
        self.assertTrue(all(not request[3] for request in ct.requests))

    def test_missing_foreign_or_malformed_entries_resolve_to_none(self):
        p = plan()
        prepared = kernel.prepare_lookup(p)
        query = [("udp", p["guest"] + ":45000")]
        self.assertEqual(kernel.exact_queries(prepared, ExactConntrack(), query), [None])
        for key, value in (("mark", 0), ("zone", 1), ("status", 0x108)):
            forged = entry()
            forged[key] = value
            with self.subTest(key=key):
                self.assertEqual(kernel.exact_queries(prepared, ExactConntrack(forged), query), [None])
        unlisted = entry()
        unlisted["original"] = (17, p["guest"], 44000, "192.0.2.9", 443)
        self.assertEqual(kernel.exact_queries(prepared, ExactConntrack(unlisted), query), [None])

    def test_kernel_answer_must_be_unique_and_match_the_asked_tuple(self):
        p = plan()
        prepared = kernel.prepare_lookup(p)
        query = [("udp", p["guest"] + ":45000")]
        with self.assertRaisesRegex(kernel.Failure, "ambiguous_exact_conntrack_lookup"):
            kernel.exact_queries(prepared, ExactConntrack(entry(), extra=[encoded_entry(entry(identifier=2))]), query)

        class WrongTuple(ExactConntrack):
            def request(self, command, flags, payload=b"", ipv6=False):
                other = entry(peer=45009)
                return [encoded_entry(other)]

        self.assertEqual(kernel.exact_queries(prepared, WrongTuple(), query), [None])

    def test_other_kernel_errors_fail_the_lookup(self):
        p = plan()

        class Broken(ExactConntrack):
            def request(self, command, flags, payload=b"", ipv6=False):
                raise OSError(kernel.errno.EPERM, "Operation not permitted")

        with self.assertRaises(OSError):
            kernel.exact_queries(kernel.prepare_lookup(p), Broken(), [("udp", p["guest"] + ":45000")])

    def test_ipv6_exact_lookup_uses_the_ipv6_family_and_ownership(self):
        p = comprehensive_plan()
        p["ipv6"] = {"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"}
        value = {
            "original": (17, "2001:db8:1::2", 44000, "2001:db8:2::9", 443),
            "reply": (17, "fe80::1", 43771, "2001:db8:1::2", 45000),
            "mark": p["cookie"],
            "id": 1,
            "zone": 0,
            "tuple_zones": (0, 0),
            "status": 0x188 | 0x20,
        }

        def encoded6(entry6):
            result = bytes([kernel.socket.AF_INET6, 0, 0, 0])
            result += kernel.attribute(kernel.CTA_ORIG, kernel.encode_tuple(entry6["original"], True), True)
            result += kernel.attribute(kernel.CTA_REPLY, kernel.encode_tuple(entry6["reply"], True), True)
            result += kernel.attribute(kernel.CTA_MARK, struct.pack("!I", entry6["mark"]))
            result += kernel.attribute(kernel.CTA_STATUS, struct.pack("!I", entry6["status"]))
            return result + kernel.attribute(kernel.CTA_ID, struct.pack("!I", entry6["id"]))

        class Exact6:
            def __init__(self, *values):
                self.values, self.requests = values, []

            def request(self, command, flags, payload=b"", ipv6=False):
                self.requests.append(ipv6)
                for item in self.values:
                    if payload == kernel.attribute(kernel.CTA_REPLY, kernel.encode_tuple(item["reply"], True), True):
                        return [encoded6(item)]
                raise OSError(kernel.errno.ENOENT, "No such file or directory")

        ct = Exact6(value)
        query = [("udp", "[2001:db8:1::2]:45000"), ("udp", "[2001:db8:1::2]:45001")]
        self.assertEqual(kernel.exact6_queries(p, ct, query), ["[2001:db8:2::9]:443", None])
        self.assertEqual(ct.requests, [True, True])
        foreign = copy.deepcopy(value)
        foreign["mark"] = 0
        self.assertEqual(kernel.exact6_queries(p, Exact6(foreign), query[:1]), [None])
        with self.assertRaises(kernel.Failure):
            kernel.exact6_queries(p, Exact6(value), [("udp", "[2001:db8:1::3]:45000")])

    def test_query_validation_stays_strict(self):
        p = plan()
        prepared = kernel.prepare_lookup(p)
        for protocol, peer in (("UDP", p["guest"] + ":45000"), ("udp", "172.28.80.1:45000"), ("udp", p["guest"] + ":045000")):
            with self.subTest(protocol=protocol, peer=peer), self.assertRaises(kernel.Failure):
                kernel.exact_queries(prepared, ExactConntrack(entry()), [(protocol, peer)])


class FirewallTests(unittest.TestCase):
    def test_restore_preserves_xtables_negation_token(self):
        with patch.object(kernel, "run") as run:
            kernel.transaction("filter", [["-I", "OUTPUT", "!", "-d", "127.0.0.0/8", "-j", "DROP"]], test=True)
        self.assertEqual(run.call_args.args[1], "*filter\n-I OUTPUT ! -d 127.0.0.0/8 -j DROP\nCOMMIT\n")

    def test_other_bridges_pass_untouched_in_every_mode(self):
        # Decision 24: until a per-network rule names one of the target's own
        # Docker bridges, forwarded traffic is neither redirected nor dropped.
        managed6 = comprehensive_plan()
        managed6["ipv6"] = {"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"}
        cases = [
            ("WPM2B_12345678", "WPM2FB_12345678", kernel.artifacts(comprehensive_plan())),
            ("WPM2VB_12345678", "WPM2VFB_12345678", kernel.ipv6_artifacts(managed6)[2:]),
        ]
        for bridge_chain, bridge_gate, parts in cases:
            hooks, body, guards = parts[-3], parts[-2], parts[-1]
            with self.subTest(bridge_chain=bridge_chain):
                prerouting = [rule for rule in hooks if rule[1] == "PREROUTING"]
                self.assertEqual(len(prerouting), 2)
                self.assertTrue(all(rule[-1] == bridge_chain for rule in prerouting))
                self.assertEqual([rule[-1] for rule in body if rule[1] == bridge_chain], ["RETURN"])
                self.assertEqual([rule[-1] for rule in guards if rule[1] == bridge_gate], ["RETURN"])
                self.assertFalse([rule for rule in guards if rule[1] == "FORWARD" and rule[-1] == "DROP"])
        blocked = kernel.ipv6_guards(comprehensive_plan())
        self.assertFalse([rule for rule in blocked if rule[1] == "FORWARD" and rule[-1] == "DROP"])
        self.assertEqual([rule[-1] for rule in blocked if rule[1] == "WPM2VFB_12345678"], ["RETURN"])
        # Replies to connections opened from elsewhere, such as published
        # ports, pass before anything else in the gate.
        gate = [rule for rule in kernel.artifacts(comprehensive_plan())[4] if rule[1] == "WPM2F_12345678"]
        self.assertIn("REPLY", gate[0])
        self.assertEqual(gate[0][-1], "RETURN")

    def test_an_older_versions_rules_are_removed_but_never_complete(self):
        # The rules come from the older scripts themselves (legacy_rules.json),
        # not from kernel.legacy_rules, so this is not checked against itself.
        with open(LEGACY_RULES, encoding="utf-8") as handle:
            fixture = json.load(handle)
        foreign = fixture["foreign"]
        for name, installed in fixture["installed"].items():
            p = legacy_plan(name)
            with self.subTest(name=name):
                old, old6 = copy.deepcopy(installed["v4"]), copy.deepcopy(installed["v6"])
                # An older version wrote the legacy tables (decision 37).
                present, rules = kernel.inspect_firewall(p, old, True, backend="legacy")
                _, ipv6_rules = kernel.inspect_firewall(p, old6, True, ipv6=True, backend="legacy")
                self.assertTrue(present)
                instance = sum(len(table["rules"]) for family in ("v4", "v6") for table in installed[family].values()) - sum(len(table["rules"]) for family in ("v4", "v6") for table in foreign[family].values())
                self.assertEqual(sum(len(found) for both in (rules, ipv6_rules) for found in both.values()), instance)
                self.assertFalse(kernel.rules_complete(p, present, rules, ipv6_rules))
                # Not an install target either: nothing of this instance may exist.
                with self.assertRaises(kernel.Failure):
                    kernel.inspect_firewall(p, old, False, backend="legacy")
                state = copy.deepcopy(installed)

                def legacy_only(table, lines, test=False, ipv6=False, backend="nft"):
                    self.assertEqual(backend, "legacy")
                    apply_removal(state, table, lines, test, ipv6)

                operation = request(p)
                operation["operation"] = "remove"
                with patch.object(kernel, "guest_lock"), patch.object(kernel, "grant"), patch.object(kernel, "guard"), patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", return_value={}), patch.object(kernel, "legacy_firewall", side_effect=lambda ipv6=False: copy.deepcopy(state["v6" if ipv6 else "v4"])), patch.object(kernel, "transaction", side_effect=legacy_only):
                    conntrack.return_value.dump.return_value = []
                    self.assertTrue(kernel.execute(operation)["ok"])
                self.assertEqual(state, foreign)

    def test_only_this_takeovers_flows_pass_and_older_tcp_is_reset(self):
        # Decision 29: a flow the target opened before the takeover carries no
        # mark, so it never passes; its TCP gets a reset, the rest is dropped.
        p = comprehensive_plan()
        p["ipv6"] = {"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"}
        mark = f"0x{p['cookie']:x}"
        for guards, guard_chain in ((kernel.artifacts(p)[4], "WPM2G_12345678"), (kernel.ipv6_artifacts(p)[5], "WPM2VG_12345678")):
            with self.subTest(guard_chain=guard_chain):
                chain = [rule for rule in guards if rule[1] == guard_chain]
                established = [rule for rule in chain if "ESTABLISHED,RELATED" in rule]
                self.assertTrue(established)
                for rule in established:
                    at = rule.index("connmark")
                    self.assertEqual(rule[at - 1:at + 3], ["-m", "connmark", "--mark", mark])
                    self.assertEqual(rule[-1], "RETURN")
                reset, drop = chain[-2], chain[-1]
                self.assertEqual(reset[reset.index("-p") + 1], "tcp")
                self.assertEqual(reset[reset.index("--ctstate") + 1], "ESTABLISHED")
                self.assertEqual(reset[reset.index("--ctdir") + 1], "ORIGINAL")
                self.assertEqual(reset[-4:], ["-j", "REJECT", "--reject-with", "tcp-reset"])
                self.assertEqual(drop[-2:], ["-j", "DROP"])
                self.assertNotIn("-p", drop)
                for rule in chain:
                    kernel.rule_key(rule)
        # Without an IPv6 plan the target's IPv6 is dropped outright, old
        # flows included: there is no established accept to narrow.
        blocked = kernel.ipv6_guards(comprehensive_plan())
        self.assertFalse([rule for rule in blocked if "ESTABLISHED,RELATED" in rule and rule[1] == "OUTPUT"])

    def test_an_installation_without_the_marked_accepts_is_this_instances_but_incomplete(self):
        p = comprehensive_plan()
        p["ipv6"] = {"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"}
        tables, tables6 = snapshot(p), ipv6_full_snapshot(p)
        old = kernel.legacy_guard_rules(p)
        old6 = kernel.legacy_guard_rules(p, ipv6=True)
        self.assertEqual(len(old), 4)
        self.assertEqual(len(old6), 2)
        for table, unmarked in ((tables, old), (tables6, old6)):
            rules = table["filter"]["rules"]
            marked = [rule for rule in rules if "ESTABLISHED,RELATED" in rule and rule[1].startswith(("WPM2G_", "WPM2VG_"))]
            for before, after in zip(marked, unmarked):
                rules[rules.index(before)] = after
            rules[:] = [rule for rule in rules if "REJECT" not in rule]
        present, found = kernel.inspect_firewall(p, tables, True)
        _, found6 = kernel.inspect_firewall(p, tables6, True, ipv6=True)
        self.assertTrue(present)
        for rule in old:
            self.assertIn(rule, found["filter"])
        for rule in old6:
            self.assertIn(rule, found6["filter"])
        self.assertFalse(kernel.rules_complete(p, present, found, found6))
        # Today's own installation is complete.
        present, found = kernel.inspect_firewall(p, snapshot(p), True)
        _, found6 = kernel.inspect_firewall(p, ipv6_full_snapshot(p), True, ipv6=True)
        self.assertTrue(kernel.rules_complete(p, present, found, found6))

    def test_ipv6_artifacts_include_nat_and_forward_gate(self):
        p = comprehensive_plan()
        p["ipv6"] = {
            "guest": "2001:db8:1::2",
            "ingress": "[fe80::1%2]:43771",
        }
        chain, guard, _, hooks, body, guards = kernel.ipv6_artifacts(p)
        self.assertTrue(chain.startswith("WPM2V_"))
        self.assertTrue(guard.startswith("WPM2VG_"))
        self.assertTrue(any(rule[1] == "PREROUTING" for rule in hooks))
        self.assertTrue(any("DNAT" in rule for rule in body))
        # Forwarded traffic goes through the gate chain; nothing on the
        # built-in FORWARD chain drops by itself (decision 24).
        self.assertEqual([rule[-1] for rule in guards if rule[1] == "FORWARD"], ["WPM2VF_12345678"])
        self.assertEqual([rule[-1] for rule in guards if rule[1] == "WPM2VFB_12345678"], ["RETURN"])
        for rule in hooks + body + guards:
            kernel.rule_key(rule)

    def snapshot(self, p=None):
        return snapshot(p)

    def test_full_and_partial_owned_artifacts(self):
        for remove_nat, remove_filter in ((False, False), (True, False), (False, True)):
            tables = self.snapshot()
            if remove_nat:
                del tables["nat"]
            if remove_filter:
                del tables["filter"]
            kernel.inspect_firewall(plan(), tables, True)
            with self.assertRaises(kernel.Failure):
                kernel.inspect_firewall(plan(), tables, False)
        self.assertEqual(kernel.inspect_firewall(plan(), {}, True), (False, {"nat": [], "filter": [], "mangle": []}))

    def test_semantically_canonical_save_order_is_accepted_not_broader_rules(self):
        tables = self.snapshot()
        rule = tables["filter"]["rules"][0]
        index = rule.index("--ctorigdst")
        rule[index + 1] += "/32"
        index = rule.index("--ctdir")
        pair = rule[index:index + 2]
        del rule[index:index + 2]
        rule.extend(pair)
        kernel.inspect_firewall(plan(), tables, True)
        index = rule.index("--ctorigdst")
        rule[index + 1] = "172.28.80.0/24"
        with self.assertRaises(kernel.Failure):
            kernel.inspect_firewall(plan(), tables, True)

    def test_observed_legacy_save_conntrack_order_is_owned(self):
        p = plan()
        tag = kernel.artifacts(p)[1]
        saved = (
            '-A OUTPUT -s 172.28.83.138/32 -p udp -m cgroup --path "/" '
            '-m conntrack --ctstate NEW --ctorigsrc 172.28.83.138 '
            '--ctorigdst 172.28.83.138 --ctorigdstport 43772 --ctdir ORIGINAL '
            f'-m mark --mark 0x{p["cookie"]:x} -m comment --comment "{tag}" -j DROP'
        )
        tables = self.snapshot(p)
        tables["filter"]["rules"] = [kernel.shlex.split(saved)]
        present, found = kernel.inspect_firewall(p, tables, True)
        self.assertTrue(present)
        self.assertEqual(found["filter"], [kernel.shlex.split(saved)])

    def test_foreign_chain_references_tags_and_mark_collisions_are_rejected(self):
        tables = self.snapshot()
        chain = kernel.artifacts(plan())[0]
        tables["nat"]["rules"].append(["-A", "OUTPUT", "-j", chain])
        with self.assertRaises(kernel.Failure):
            kernel.inspect_firewall(plan(), tables, True)
        tables = self.snapshot()
        tables["nat"]["rules"][0].extend(["--sport", "12345"])
        with self.assertRaises(kernel.Failure):
            kernel.inspect_firewall(plan(), tables, True)
        self.assertTrue(kernel.mark_mentions(["--set-xmark", "0x12345678/0xffffffff"], plan()["cookie"]))
        self.assertTrue(kernel.mark_mentions(["--mark", "0x12000000/0xff000000"], plan()["cookie"]))
        self.assertFalse(kernel.mark_mentions(["--mark", "0x0"], plan()["cookie"]))

    def test_other_generations_foreign_cgroup_shapes_are_not_parsed(self):
        for p in (plan(), comprehensive_plan()):
            other = copy.deepcopy(p)
            other["cookie"] += 1
            other["target"]["name"] = "WSLProxyLab-Control"
            tables = snapshot(other)
            for table in tables.values():
                for rule in table["rules"]:
                    if "--path" in rule:
                        rule[rule.index("--path") + 1] = "../../unreachable/from/another/namespace"
                    rule.extend(["--foreign-extension", "shape-not-owned"])
            self.assertEqual(kernel.inspect_firewall(p, tables, False), (False, {"nat": [], "filter": [], "mangle": []}))
            if p.get("system_dns") is not None:
                v6 = ipv6_snapshot(other)
                v6["filter"]["rules"][0].extend(["--foreign-extension", "not-owned"])
                kernel.inspect_firewall(p, v6, False, ipv6=True)

    def test_duplicate_live_tags_and_mismatched_plan_digest_refuse(self):
        for p in (plan(), comprehensive_plan()):
            tables = snapshot(p)
            tables["filter"]["rules"].append(copy.deepcopy(tables["filter"]["rules"][0]))
            with self.subTest(mode=p.get("system_dns")), self.assertRaises(kernel.Failure):
                kernel.inspect_firewall(p, tables, True)
            changed = copy.deepcopy(p)
            changed["ingress"] = "172.28.80.1:43780"
            with self.assertRaises(kernel.Failure):
                kernel.inspect_firewall(changed, snapshot(p), True)
        opposite_mode = {"nat": {"chains": {"WPM2_12345678": "-"}, "rules": []}}
        with self.assertRaises(kernel.Failure):
            kernel.inspect_firewall(plan(), opposite_mode, True)

    def test_foreign_mark_negation_and_corruption_fail_closed(self):
        cookie = plan()["cookie"]
        self.assertTrue(kernel.mark_mentions(["!", "--mark", "0x1"], cookie))
        self.assertFalse(kernel.mark_mentions(["!", "--mark", hex(cookie)], cookie))
        for rule in (["--mark"], ["--mark", "garbled"], ["--mark", "1/2/3"], ["--mark", "0x100000000"]):
            with self.subTest(rule=rule), self.assertRaises(kernel.Failure):
                kernel.mark_mentions(rule, cookie)

    def test_an_empty_name_collision_is_not_proof_of_owned_chain(self):
        tables = self.snapshot()
        tables["nat"]["rules"] = []
        with self.assertRaises(kernel.Failure):
            kernel.inspect_firewall(plan(), tables, True)

    def test_first_packet_marking_and_precise_guard_install_order(self):
        p = plan()
        chain, _, hooks, body, guards = kernel.artifacts(p)
        self.assertTrue(all("--mark" not in rule for rule in hooks))
        self.assertEqual(body[0][body[0].index("--mark") + 1], "0x0")
        self.assertEqual([rule[rule.index("-p") + 1] for rule in body if "DNAT" in rule], ["tcp", "udp"])
        self.assertEqual(body[-1][body[-1].index("-j") + 1], "MARK")
        self.assertTrue(all("--ctorigdst" in rule and rule[-1] == "DROP" for rule in guards))
        with patch.object(kernel, "transaction") as transact:
            kernel.install_rules(p, test=True)
        first, second = transact.call_args_list
        self.assertEqual(first.args[0], "filter")
        self.assertEqual(second.args[0], "nat")
        self.assertEqual(second.args[1][0], ["-N", chain])
        self.assertTrue(all(rule[:3] == ["-I", "OUTPUT", "1"] for rule in first.args[1]))
        self.assertNotIn(":" + chain, str(second.args[1]))

    def test_comprehensive_guards_cover_fallback_and_preserve_inbound_replies(self):
        p = comprehensive_plan()
        chain, _, hooks, body, guards = kernel.artifacts(p)
        self.assertEqual(chain, "WPM2_12345678")
        self.assertEqual([rule[rule.index("-p") + 1] for rule in body if "DNAT" in rule], ["tcp", "udp"])
        output = [rule for rule in hooks if rule[1] == "OUTPUT" and "-j" in rule]
        self.assertTrue(all("--path" in rule and "--ctdir" in rule for rule in output))
        regular = [rule for rule in output if "-s" in rule]
        self.assertTrue(all("--dport" not in rule for rule in regular))
        self.assertTrue(all(rule[rule.index("--ctdir") + 1] == "ORIGINAL" for rule in output))
        reply_guard = next(rule for rule in guards if "--ctdir" in rule and rule[rule.index("--ctdir") + 1] == "REPLY")
        self.assertEqual(reply_guard[-1], "RETURN")
        # The probe's counting rule comes first: the guard jump after it
        # drops the probe, which must be counted before (decision 37).
        self.assertNotIn("-j", guards[0])
        self.assertIn("240.0.0.1/32", guards[0])
        self.assertIn("--ctorigdst", guards[1])
        self.assertIn("!", guards[1])
        self.assertEqual(guards[-1][-1], "DROP")
        # Apart from conntrack replies, a guard RETURN lets a packet leave
        # directly. Only proven TCP/UDP tuples may do so; ICMP and other
        # protocols must reach the final DROP on both address families.
        v6_plan = dict(p, ipv6={"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"})
        _, v6_guard_chain, _, _, _, v6_guards = kernel.ipv6_artifacts(v6_plan)
        for chain_name, family in (("WPM2G_12345678", guards), (v6_guard_chain, v6_guards)):
            exits = [rule for rule in family if rule[1] == chain_name and rule[-1] == "RETURN" and "REPLY" not in rule]
            self.assertTrue(exits)
            self.assertTrue(all("-p" in rule and rule[rule.index("-p") + 1] in ("tcp", "udp") for rule in exits))
            self.assertEqual([rule[-1] for rule in family if rule[1] == chain_name][-1], "DROP")
        established = [rule for rule in guards if "ESTABLISHED,RELATED" in rule]
        self.assertTrue(all("-p" in rule and rule[rule.index("-p") + 1] in ("tcp", "udp") for rule in established))
        self.assertTrue(
            all(
                "--ctorigsrc" in rule or ("--ctorigdst" in rule and "--ctorigdstport" in rule)
                for rule in established
                if rule[1] != "WPM2F_12345678"
            )
        )
        self.assertTrue(any(rule[1] == "WPM2F_12345678" and rule[-1] == "ACCEPT" for rule in established))
        snat = [rule for rule in hooks if "SNAT" in rule]
        self.assertEqual(len(snat), 2)
        for rule in snat:
            self.assertEqual(rule[rule.index("-d") + 1], kernel.endpoint(p["ingress"])[0] + "/32")
            self.assertEqual(rule[rule.index("--to-source") + 1], p["guest"])
            self.assertIn("connmark", rule)
        with patch.object(kernel, "transaction") as transact:
            kernel.install_rules(p, test=True)
        # Guards and the FORWARD gate (in mangle, decision 37) before redirection.
        self.assertEqual(
            [(call.args[0], call.kwargs.get("ipv6", False)) for call in transact.call_args_list],
            [("filter", False), ("mangle", False), ("filter", True), ("mangle", True), ("nat", False)],
        )

    def test_managed_ipv6_guards_go_ahead_of_existing_output_accepts(self):
        # A pre-existing ACCEPT ahead of an appended jump would let ICMPv6 and
        # other non-TCP/UDP packets leave before the guard's final DROP.
        p = comprehensive_plan()
        p["ipv6"] = {"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"}
        _, v6_guard, _, _, _, _ = kernel.ipv6_artifacts(p)
        with patch.object(kernel, "transaction") as transact:
            kernel.install_rules(p, test=True)
        filters = [call.args[1] for call in transact.call_args_list if call.args[0] == "filter"]
        self.assertEqual(len(filters), 2)
        for lines in filters:
            output = [line for line in lines if "OUTPUT" in line[:2]]
            self.assertTrue(output)
            self.assertTrue(all(line[:3] == ["-I", "OUTPUT", "1"] for line in output))
        v6_filter = next(
            call.args[1]
            for call in transact.call_args_list
            if call.args[0] == "filter" and call.kwargs.get("ipv6")
        )
        self.assertEqual(v6_filter[0], ["-N", v6_guard])
        self.assertTrue(any(line[:2] == ["-A", v6_guard] for line in v6_filter))
        self.assertFalse(any("FORWARD" in line[:2] for line in v6_filter))
        v6_gate = next(call.args[1] for call in transact.call_args_list if call.args[0] == "mangle" and call.kwargs.get("ipv6"))
        self.assertTrue(all(line[:3] == ["-I", "FORWARD", "1"] for line in v6_gate if "FORWARD" in line[:2]))

    def test_comprehensive_partial_recovery_requires_exact_ipv4_and_ipv6_shapes(self):
        p = comprehensive_plan()
        tables = self.snapshot(p)
        kernel.inspect_firewall(p, tables, True)
        del tables["nat"]  # Guard phase committed, NAT phase failed.
        kernel.inspect_firewall(p, tables, True)
        with self.assertRaises(kernel.Failure):
            kernel.inspect_firewall(p, tables, False)
        reordered = next(rule for rule in tables["filter"]["rules"] if "ESTABLISHED,RELATED" in rule)
        index = reordered.index("--ctstate")
        reordered[index + 1] = "RELATED,ESTABLISHED"
        kernel.inspect_firewall(p, tables, True)
        guards = kernel.ipv6_guards(p)
        ipv6 = {table: {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(rules)} for table, rules in kernel.split_guards(guards).items()}
        kernel.inspect_firewall(p, ipv6, True, ipv6=True)
        output_guards = [rule for rule in guards if rule[1] == "OUTPUT"]
        self.assertTrue(all("::1/128" in rule and "cgroup" in rule for rule in output_guards))
        self.assertEqual([rule[-1] for rule in guards if rule[1] == "FORWARD"], ["WPM2VF_12345678"])
        ipv6["filter"]["rules"][0].remove("!")
        with self.assertRaises(kernel.Failure):
            kernel.inspect_firewall(p, ipv6, True, ipv6=True)

    def test_partial_install_removal_deletes_only_recorded_rules_and_chains(self):
        p = comprehensive_plan()
        partial = self.snapshot(p)
        del partial["nat"]
        v6 = {table: {"chains": {"OUTPUT": "ACCEPT"}, "rules": rules} for table, rules in kernel.split_guards(kernel.ipv6_guards(p)).items()}
        operation = request(p)
        operation["operation"] = "remove"
        with patch.object(kernel, "guest_lock"), patch.object(kernel, "grant"), patch.object(kernel, "guard") as guard, patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=[partial, v6, {}, {}]), patch.object(kernel, "transaction") as transact:
            conntrack.return_value.dump.return_value = []
            kernel.execute(operation)
        guard.assert_called_once_with(p, check_resolver=False, write_tools=True)
        ipv4 = [call for call in transact.call_args_list if not call.kwargs.get("ipv6")]
        self.assertEqual([call.args[0] for call in ipv4], ["filter", "mangle"])
        self.assertEqual({line[1] for line in ipv4[0].args[1] if line[0] == "-X"}, {"WPM2G_12345678"})
        self.assertEqual({line[1] for line in ipv4[1].args[1] if line[0] == "-X"}, {"WPM2F_12345678", "WPM2FB_12345678"})
        self.assertTrue(any(call.kwargs.get("ipv6") for call in transact.call_args_list))
        self.assertTrue(all(rule[0] in ("-D", "-X") for call in transact.call_args_list for rule in call.args[1]))

    def test_stale_remove_recovers_after_any_identity_or_environment_drift_with_exact_rules(self):
        for reason in (
            "boot_changed",
            "cgroup_namespace_changed",
            "cgroup_root_changed",
            "guest_address_changed",
            "gateway_changed_or_ambiguous",
            "distribution_name_changed",
            "guest_ipv6_address_changed",
            "workload_outside_distro_cgroup",
            "unverifiable_workload",
        ):
            with self.subTest(reason=reason):
                p = plan()
                operation = request(p)
                operation["operation"] = "remove"
                with (
                    patch.object(kernel, "guest_lock"),
                    patch.object(kernel, "guard", side_effect=kernel.Failure(reason)) as guard,
                    patch.object(kernel, "grant") as grant,
                    patch.object(kernel, "Conntrack") as conntrack,
                    patch.object(kernel, "firewall", side_effect=[snapshot(p), {}]),
                    patch.object(kernel, "transaction") as transact,
                ):
                    conntrack.return_value.dump.return_value = []
                    result = kernel.execute(operation)
                self.assertEqual(result, {"ok": True, "operation": "remove", "identity_error": reason, "unproven_mappings": 0})
                guard.assert_called_once_with(p, check_resolver=False, write_tools=True)
                grant.assert_called_once_with(p, "revoke")
                self.assertTrue(transact.call_args_list)
                self.assertTrue(
                    all(
                        rule[0] in ("-D", "-X")
                        for call in transact.call_args_list
                        for rule in call.args[1]
                    )
                )
                conntrack.return_value.delete.assert_not_called()

    def test_stale_remove_rejects_foreign_same_cookie_firewall(self):
        for reason in ("cgroup_namespace_changed", "workload_outside_distro_cgroup"):
            with self.subTest(reason=reason):
                p = plan()
                foreign = copy.deepcopy(p)
                foreign["ingress"] = "172.28.80.1:43780"
                operation = request(p)
                operation["operation"] = "remove"
                with (
                    patch.object(kernel, "guest_lock"),
                    patch.object(kernel, "guard", side_effect=kernel.Failure(reason)) as guard,
                    patch.object(kernel, "grant") as grant,
                    patch.object(kernel, "Conntrack") as conntrack,
                    patch.object(kernel, "firewall", return_value=snapshot(foreign)),
                    patch.object(kernel, "transaction") as transact,
                ):
                    with self.assertRaisesRegex(kernel.Failure, "foreign_instance_rule"):
                        kernel.execute(operation)
                guard.assert_called_once_with(p, check_resolver=False, write_tools=True)
                grant.assert_called_once_with(p, "revoke")
                transact.assert_not_called()
                conntrack.return_value.delete.assert_not_called()

    def test_stale_remove_leaves_and_counts_an_unprovable_same_cookie_mapping(self):
        # Decision 20: an entry with this mark that cannot be proven ours is
        # never deleted, and no longer makes the stop fail.
        for reason in ("cgroup_namespace_changed", "workload_outside_distro_cgroup"):
            with self.subTest(reason=reason):
                p = plan()
                foreign = entry(p)
                foreign["original"] = (17, p["guest"], 44000, "172.28.80.2", 43772)
                operation = request(p)
                operation["operation"] = "remove"
                with (
                    patch.object(kernel, "guest_lock"),
                    patch.object(kernel, "guard", side_effect=kernel.Failure(reason)) as guard,
                    patch.object(kernel, "grant") as grant,
                    patch.object(kernel, "Conntrack") as conntrack,
                    patch.object(kernel, "firewall", return_value={}),
                    patch.object(kernel, "transaction") as transact,
                ):
                    conntrack.return_value.dump.return_value = [foreign]
                    result = kernel.execute(operation)
                self.assertEqual(result, {"ok": True, "operation": "remove", "identity_error": reason, "unproven_mappings": 1})
                guard.assert_called_once_with(p, check_resolver=False, write_tools=True)
                grant.assert_called_once_with(p, "revoke")
                transact.assert_not_called()
                conntrack.return_value.delete.assert_not_called()

    def test_install_paths_still_refuse_every_guard_failure(self):
        for operation_name in ("precheck", "install", "arm"):
            for reason in ("workload_outside_distro_cgroup", "boot_changed", "distribution_name_changed"):
                with self.subTest(operation=operation_name, reason=reason):
                    p = plan()
                    operation = request(p)
                    operation["operation"] = operation_name
                    if operation_name == "arm":
                        operation["deadline"] = int(time.time()) + 10
                    with (
                        patch.object(kernel, "guest_lock"),
                        patch.object(kernel, "guard", side_effect=kernel.Failure(reason)),
                        patch.object(kernel, "grant") as grant,
                        patch.object(kernel, "Conntrack") as conntrack,
                        patch.object(kernel, "install_rules") as install,
                        patch.object(kernel, "transaction") as transact,
                    ):
                        with self.assertRaisesRegex(kernel.Failure, reason):
                            kernel.execute(operation)
                    grant.assert_not_called()
                    install.assert_not_called()
                    transact.assert_not_called()
                    conntrack.assert_not_called()


class FakeTables:
    """Both address families of a guest's legacy tables, applying restore
    documents as iptables would: -N, -A, -I <chain> 1, -D, -X."""

    def __init__(self, v4=None, v6=None, legacy_v4=None, legacy_v6=None):
        self.state = {"v4": copy.deepcopy(v4 or {}), "v6": copy.deepcopy(v6 or {})}
        self.legacy_state = {"v4": copy.deepcopy(legacy_v4 or {}), "v6": copy.deepcopy(legacy_v6 or {})}

    def firewall(self, ipv6=False):
        return copy.deepcopy(self.state["v6" if ipv6 else "v4"])

    def legacy(self, ipv6=False):
        return copy.deepcopy(self.legacy_state["v6" if ipv6 else "v4"])

    def transaction(self, table, lines, test=False, ipv6=False, backend="nft"):
        if test:
            return
        family = (self.state if backend == "nft" else self.legacy_state)["v6" if ipv6 else "v4"]
        current = family.setdefault(table, {"chains": {"OUTPUT": "ACCEPT"}, "rules": []})
        rules = current["rules"]
        for line in lines:
            if line[0] == "-N":
                current["chains"][line[1]] = "-"
            elif line[0] == "-A":
                rules.append(list(line))
            elif line[0] == "-I":
                assert line[2] == "1", line
                first = next((index for index, rule in enumerate(rules) if rule[1] == line[1]), len(rules))
                rules.insert(first, ["-A", line[1], *line[3:]])
            elif line[0] == "-D":
                rules.remove(["-A", *line[1:]])
            elif line[0] == "-X":
                assert not any(rule[1] == line[1] or rule[-1] == line[1] for rule in rules), line
                del current["chains"][line[1]]
            else:
                raise AssertionError(line)

    def rules(self, tag):
        return [rule for state in (self.state, self.legacy_state) for family in state.values() for table in family.values() for rule in table["rules"] if tag in rule]


class BlockTests(unittest.TestCase):
    """Decision 33: the drop-only rules of a lost managed takeover."""

    def execute(self, p, operation_name, fake, drift="boot_changed"):
        operation = request(p)
        operation["operation"] = operation_name
        failure = kernel.Failure(drift) if drift else None
        with (
            patch.object(kernel, "guest_lock"),
            patch.object(kernel, "guard", side_effect=failure),
            patch.object(kernel, "grant"),
            patch.object(kernel, "grant_pending", return_value=False),
            patch.object(kernel, "Conntrack") as conntrack,
            patch.object(kernel, "docker_networks", return_value=None),
            patch.object(kernel, "firewall", side_effect=fake.firewall),
            patch.object(kernel, "legacy_firewall", side_effect=fake.legacy),
            patch.object(kernel, "transaction", side_effect=fake.transaction),
        ):
            conntrack.return_value.dump.return_value = []
            return kernel.execute(operation)

    def blocked(self, p, fake):
        return fake.rules(kernel.block_tag(p)) + fake.rules(kernel.block_tag(p, ipv6=True))

    def test_block_after_a_vm_restart_drops_the_targets_traffic_once(self):
        for ipv6 in (None, {"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"}):
            with self.subTest(managed_ipv6=ipv6 is not None):
                p = comprehensive_plan()
                if ipv6 is not None:
                    p["ipv6"] = ipv6
                fake = FakeTables()  # a new VM: nothing of this takeover left
                self.assertEqual(self.execute(p, "block", fake), {"ok": True, "operation": "block", "blocked": {"rules": 4}})
                rules = self.blocked(p, fake)
                self.assertEqual(sorted(map(kernel.rule_key, rules)), sorted(map(kernel.rule_key, kernel.block_rules(p) + kernel.block_rules(p, ipv6=True))))
                # Drops everything the target starts except to loopback,
                # including the system DNS address.
                self.assertTrue(all(rule[-1] == "DROP" and ["-m", "cgroup", "--path", "/"] == rule[2:6] for rule in rules))
                self.assertFalse(any(p["system_dns"] in rule for rule in rules))
                # Again: replaced in one transaction per family, never doubled.
                calls = []
                original = fake.transaction
                with patch.object(fake, "transaction", side_effect=lambda *a, **k: (calls.append((a, k)), original(*a, **k))):
                    self.assertEqual(self.execute(p, "block", fake)["blocked"], {"rules": 4})
                self.assertEqual(len(calls), 2)
                for (table, lines), _ in calls:
                    self.assertEqual([line[0] for line in lines], ["-D", "-D", "-I", "-I"])
                self.assertEqual(len(self.blocked(p, fake)), 4)

    def test_a_stop_removes_the_block_alone_or_next_to_the_old_rules(self):
        p = comprehensive_plan()
        for name, fake, drift in (
            ("vm_restarted", FakeTables(), "boot_changed"),
            ("target_restarted", FakeTables(snapshot(p), ipv6_snapshot(p)), "cgroup_namespace_changed"),
            ("rules_incomplete", FakeTables({"filter": snapshot(p)["filter"]}, ipv6_snapshot(p)), None),
        ):
            with self.subTest(name):
                self.execute(p, "block", fake, drift)
                self.assertEqual(len(self.blocked(p, fake)), 4)
                # The periodic check: still lost, never complete.
                if drift:
                    with self.assertRaisesRegex(kernel.Failure, "stale_identity_has_owned_artifacts"):
                        self.execute(p, "inspect", fake, drift)
                else:
                    ownership = self.execute(p, "inspect", fake, drift)["ownership"]
                    self.assertTrue(ownership["rules_present"])
                    self.assertFalse(ownership["rules_complete"])
                result = self.execute(p, "remove", fake, drift)
                self.assertEqual(result["unproven_mappings"], 0)
                self.assertEqual(self.blocked(p, fake), [])
                for family in fake.state.values():
                    for table in family.values():
                        self.assertEqual(table["rules"], [], name)
                        self.assertEqual(set(table["chains"]), {"OUTPUT"}, name)

    def test_a_block_rule_of_another_shape_is_refused(self):
        p = comprehensive_plan()
        fake = FakeTables()
        self.execute(p, "block", fake)
        rule = fake.state["v4"]["filter"]["rules"][0]
        rule[rule.index("DROP")] = "ACCEPT"
        with self.assertRaisesRegex(kernel.Failure, "foreign_instance_rule"):
            self.execute(p, "remove", fake)

    def test_block_is_for_a_managed_takeover_only(self):
        with self.assertRaisesRegex(kernel.Failure, "block_needs_managed_mode"):
            self.execute(plan(), "block", FakeTables())




class NftBackendTests(unittest.TestCase):
    """Decision 37: rules go in through iptables-nft, the FORWARD gate lives
    in the mangle table, and an older version's legacy rules are removed."""

    execute = BlockTests.execute
    foreign = ["-m", "comment", "--comment", "another tool", "-j", "ACCEPT"]

    def ahead(self, tables, table, chain):
        tables.setdefault(table, {"chains": {}, "rules": []})["rules"].insert(0, ["-A", chain, *self.foreign])
        return tables

    def ownership(self, p, v4, v6=None):
        return self.execute(p, "inspect", FakeTables(v4, v6 if v6 is not None else ipv6_snapshot(p)), drift=None)["ownership"]

    def test_a_rule_ahead_of_the_guard_is_incomplete_ahead_of_the_gate_displaced_and_nat_ignored(self):
        p = comprehensive_plan()
        clean = self.ownership(p, snapshot(p))
        self.assertTrue(clean["rules_complete"])
        self.assertFalse(clean["forward_displaced"])
        # Another tool's accept ahead of the OUTPUT guard: as good as no guard.
        guard = self.ownership(p, self.ahead(snapshot(p), "filter", "OUTPUT"))
        self.assertFalse(guard["rules_complete"])
        self.assertTrue(guard["rules_present"])
        # Ahead of the FORWARD gate: the target is still guarded, not its containers.
        gate = self.ownership(p, self.ahead(snapshot(p), "mangle", "FORWARD"))
        self.assertTrue(gate["rules_complete"])
        self.assertTrue(gate["forward_displaced"])
        gate6 = self.ownership(p, snapshot(p), self.ahead(ipv6_snapshot(p), "mangle", "FORWARD"))
        self.assertTrue(gate6["forward_displaced"])
        # Docker's MASQUERADE on top of nat POSTROUTING, Docker's own FORWARD
        # jumps in the filter table, or another tool's rule after ours: fine.
        for table, chain in (("nat", "POSTROUTING"), ("nat", "PREROUTING"), ("filter", "FORWARD")):
            with self.subTest(table=table, chain=chain):
                value = self.ownership(p, self.ahead(snapshot(p), table, chain))
                self.assertTrue(value["rules_complete"])
                self.assertFalse(value["forward_displaced"])
        after = snapshot(p)
        after["filter"]["rules"].append(["-A", "OUTPUT", *self.foreign])
        self.assertTrue(self.ownership(p, after)["rules_complete"])

    def test_the_gate_is_in_mangle_and_install_writes_only_through_nft(self):
        p = comprehensive_plan()
        for ipv6 in (False, True):
            tables = kernel.base_tables(p, ipv6)
            self.assertTrue(tables["mangle"])
            self.assertTrue(all(kernel.gate_rule(rule) for rule in tables["mangle"]))
            self.assertFalse(any(kernel.gate_rule(rule) for rule in tables["filter"]))
        self.assertEqual(kernel.base_tables(p, backend="legacy").keys(), {"nat", "filter"})
        fake = FakeTables()
        with (
            patch.object(kernel, "transaction", side_effect=fake.transaction) as transact,
        ):
            kernel.install_rules(p)
        self.assertTrue(all(call.kwargs.get("backend", "nft") == "nft" for call in transact.call_args_list))
        self.assertEqual(fake.legacy_state, {"v4": {}, "v6": {}})
        self.assertTrue(self.execute(p, "inspect", fake, drift=None)["ownership"]["rules_complete"])

    def test_an_older_versions_legacy_rules_next_to_nft_ones_are_never_complete_and_a_stop_clears_both(self):
        p = comprehensive_plan()
        fake = FakeTables(snapshot(p), ipv6_snapshot(p), tables_of(p, backend="legacy"), tables_of(p, ipv6=True, backend="legacy"))
        value = self.execute(p, "inspect", fake, drift=None)["ownership"]
        self.assertTrue(value["rules_present"])
        self.assertFalse(value["rules_complete"])
        # Only legacy ones left (an older version's stop never ran): present.
        only_old = FakeTables(legacy_v4=tables_of(p, backend="legacy"), legacy_v6=tables_of(p, ipv6=True, backend="legacy"))
        self.assertTrue(self.execute(p, "inspect", only_old, drift=None)["ownership"]["rules_present"])
        for tables in (fake, only_old):
            self.assertEqual(self.execute(p, "remove", tables, drift=None)["unproven_mappings"], 0)
            for state in (tables.state, tables.legacy_state):
                for family in state.values():
                    for table in family.values():
                        self.assertEqual(table["rules"], [])
                        self.assertEqual(set(table["chains"]), {"OUTPUT"})


class ProbeTests(unittest.TestCase):
    """Decision 37: a probe from the target catches rules another
    distribution re-added under its own cgroup namespace; re-anchoring puts
    them back."""

    execute = BlockTests.execute

    def test_the_probe_rules_count_only_and_sit_ahead_of_the_guard(self):
        p = comprehensive_plan()
        probes = kernel.probe_rules(p)
        for table, rule in probes.items():
            self.assertNotIn("-j", rule)
            self.assertEqual(rule[rule.index("-d") + 1], "240.0.0.1/32")
            self.assertEqual(rule[rule.index("--path") + 1], "/")
        output = [rule for rule in kernel.artifacts(p)[4] if rule[1] == "OUTPUT"]
        self.assertEqual(output[0], probes["filter"])
        # The redirect chain returns 240.0.0.0/4 before marking anything.
        body = kernel.artifacts(p)[3]
        returned = next(index for index, rule in enumerate(body) if "240.0.0.0/4" in rule)
        marked = next(index for index, rule in enumerate(body) if "CONNMARK" in rule)
        self.assertLess(returned, marked)
        self.assertEqual(body[returned][-1], "RETURN")

    def test_probe_counts_read_only_the_probe_rules(self):
        p = comprehensive_plan()
        probes = kernel.probe_rules(p)
        other = ["-A", "OUTPUT", "-d", "240.0.0.1/32", "-p", "tcp", "-m", "tcp", "--dport", "9", "-m", "comment", "--comment", "someone-else"]
        dumps = {
            "nat": "# comment\n*nat\n:OUTPUT ACCEPT [0:0]\n[7:420] " + " ".join(probes["nat"]) + "\n[99:1] " + " ".join(other) + "\nCOMMIT\n",
            "filter": "*filter\n[3:180] " + " ".join(probes["filter"]).replace("--path /", '--path "/"') + "\nCOMMIT\n",
        }
        with patch.object(kernel, "run", side_effect=lambda argv, data=None, timeout=4: dumps[argv[-1]]):
            self.assertEqual(kernel.probe_counts(p), {"nat": 7, "filter": 3})

    def test_the_probe_is_bound_only_when_both_tables_count_it(self):
        p = comprehensive_plan()
        for after, bound in (({"nat": 8, "filter": 4}, True), ({"nat": 8, "filter": 3}, False), ({"nat": 7, "filter": 3}, False), ({}, False)):
            with self.subTest(after=after), patch.object(kernel, "probe_counts", side_effect=[{"nat": 7, "filter": 3}, after]), patch.object(kernel.socket, "socket") as make:
                make.return_value.connect.side_effect = BlockingIOError()
                self.assertEqual(REAL_PROBE_BOUND(p), bound)
                make.return_value.connect.assert_called_once_with(("240.0.0.1", 9))
                make.return_value.close.assert_called_once()

    def test_inspect_reports_unbound_rules_only_when_complete(self):
        p = comprehensive_plan()
        with patch.object(kernel, "probe_bound", return_value=False) as probe:
            value = self.execute(p, "inspect", FakeTables(snapshot(p), ipv6_snapshot(p)), drift=None)["ownership"]
            self.assertTrue(value["rules_complete"])
            self.assertFalse(value["rules_bound"])
            partial = snapshot(p)
            del partial["nat"]
            value = self.execute(p, "inspect", FakeTables(partial, ipv6_snapshot(p)), drift=None)["ownership"]
        self.assertTrue(value["rules_bound"])
        self.assertEqual(probe.call_count, 1)

    def test_anchor_reinserts_the_cgroup_rules_in_place_and_probes_again(self):
        for ipv6 in (None, {"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"}):
            with self.subTest(managed_ipv6=ipv6 is not None):
                p = comprehensive_plan()
                if ipv6 is not None:
                    p["ipv6"] = ipv6
                fake = FakeTables(snapshot(p), ipv6_snapshot(p))
                fake.state["v4"]["filter"]["rules"].append(["-A", "OUTPUT", "-m", "comment", "--comment", "after", "-j", "ACCEPT"])
                before = copy.deepcopy(fake.state)
                calls = []
                original = fake.transaction
                with patch.object(fake, "transaction", side_effect=lambda *a, **k: (calls.append((a, k)), original(*a, **k))), patch.object(kernel, "probe_bound", return_value=True):
                    self.assertEqual(self.execute(p, "anchor", fake, drift=None), {"ok": True, "operation": "anchor", "anchored": {"bound": True}})
                # One transaction per table that has such rules, deletes then inserts.
                for (table, lines), kwargs in calls:
                    self.assertIn(table, ("nat", "filter"))
                    kinds = [line[0] for line in lines]
                    self.assertEqual(kinds, sorted(kinds, key=lambda kind: kind != "-D"))
                    self.assertTrue(all(line[1] == "OUTPUT" and "cgroup" in line for line in lines))
                self.assertEqual(len(calls), 4 if ipv6 is not None else 3)
                for family in ("v4", "v6"):
                    for table in fake.state[family]:
                        self.assertEqual(sorted(map(kernel.rule_key, fake.state[family][table]["rules"])), sorted(map(kernel.rule_key, before[family][table]["rules"])), (family, table))
                        output = [rule for rule in fake.state[family][table]["rules"] if rule[1] == "OUTPUT"]
                        mine = [rule for rule in output if "cgroup" in rule]
                        self.assertEqual(output[:len(mine)], mine)
                self.assertTrue(self.execute(p, "inspect", fake, drift=None)["ownership"]["rules_complete"])

    def test_anchor_refuses_incomplete_rules_drift_and_scoped_mode(self):
        p = comprehensive_plan()
        partial = snapshot(p)
        del partial["nat"]
        with self.assertRaisesRegex(kernel.Failure, "anchor_without_complete_rules"):
            self.execute(p, "anchor", FakeTables(partial, ipv6_snapshot(p)), drift=None)
        with self.assertRaisesRegex(kernel.Failure, "boot_changed"):
            self.execute(p, "anchor", FakeTables(snapshot(p), ipv6_snapshot(p)), drift="boot_changed")
        with self.assertRaisesRegex(kernel.Failure, "anchor_needs_managed_mode"):
            self.execute(plan(), "anchor", FakeTables(snapshot(plan())), drift=None)

class InspectionTests(unittest.TestCase):
    def observe(self, p, tables, entries=None, ipv6_entries=None, identity_error=None, pending=False):
        operation = request(p)
        operation["operation"] = "inspect"
        failure = kernel.Failure(identity_error) if identity_error else None
        # No test may reach the host's real /proc or docker.sock.
        with patch.object(kernel, "guest_lock") as lock, patch.object(kernel, "guard", side_effect=failure) as guard, patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=tables), patch.object(kernel, "transaction") as transact, patch.object(kernel, "install_rules") as install, patch.object(kernel, "grant") as grant, patch.object(kernel, "grant_pending", return_value=pending), patch.object(kernel, "docker_networks", return_value={}):
            conntrack.return_value.dump.side_effect = lambda ipv6=False: (ipv6_entries or []) if ipv6 else (entries or [])
            try:
                return kernel.execute(operation)["ownership"]
            finally:
                lock.return_value.__enter__.assert_called_once()
                guard.assert_called_once_with(p, check_resolver=False, write_tools=False)
                transact.assert_not_called()
                install.assert_not_called()
                grant.assert_not_called()
                conntrack.return_value.delete.assert_not_called()

    def test_live_complete_and_partial_rules_are_observed_not_modified(self):
        for p in (plan(), comprehensive_plan()):
            tables = [snapshot(p)]
            if p.get("system_dns") is not None:
                tables.append(ipv6_snapshot(p))
            value = self.observe(p, tables)
            self.assertEqual(value, {"identity_matches": True, "rules_present": True, "rules_complete": True, "mappings_present": False, "unproven_mappings": 0, "forward_displaced": False, "rules_bound": True})
            partial = snapshot(p)
            del partial["nat"]
            tables = [partial] + ([ipv6_snapshot(p)] if p.get("system_dns") is not None else [])
            value = self.observe(p, tables)
            self.assertTrue(value["rules_present"])
            self.assertFalse(value["rules_complete"])

    def test_ipv6_rules_complete_checks_both_nat_families(self):
        p = comprehensive_plan()
        p["ipv6"] = {
            "guest": "2001:db8:1::2",
            "ingress": "[fe80::1%2]:43771",
        }
        value = self.observe(p, [snapshot(p), ipv6_full_snapshot(p)])
        self.assertTrue(value["rules_complete"])
        partial = ipv6_full_snapshot(p)
        partial["nat"]["rules"].pop(0)  # one hook missing
        value = self.observe(p, [snapshot(p), partial])
        self.assertFalse(value["rules_complete"])

    def test_absence_and_live_connmark_are_independently_observed(self):
        for p, values in ((plan(), [entry()]), (comprehensive_plan(), [comprehensive_entry()])):
            tables = [{}] + ([{}] if p.get("system_dns") is not None else [])
            value = self.observe(p, tables, entries=values)
            self.assertFalse(value["rules_present"])
            self.assertTrue(value["mappings_present"])
            absent = self.observe(p, tables)
            self.assertFalse(absent["rules_present"] or absent["mappings_present"] or absent["rules_complete"])

    def test_inspect_counts_unprovable_marked_mappings_without_failing(self):
        p = comprehensive_plan()
        corrupt = comprehensive_entry()
        corrupt["reply"] = (17, "172.28.80.1", 9999, p["guest"], 45000)
        value = self.observe(p, [snapshot(p), ipv6_snapshot(p)], entries=[corrupt, comprehensive_entry(port=80)])
        self.assertEqual(value["unproven_mappings"], 1)
        self.assertTrue(value["mappings_present"])
        self.assertTrue(value["rules_complete"])

    def test_bridge_dns_for_other_resolvers_is_left_to_the_forward_drop(self):
        p = comprehensive_plan()
        chain, _, _, body, guards = kernel.artifacts(p)
        skip = [rule for rule in body if "--dport" in rule and rule[rule.index("--dport") + 1] == "53"]
        self.assertEqual([rule[rule.index("-p") + 1] for rule in skip], ["tcp", "udp"])
        for rule in skip:
            self.assertEqual(rule[rule.index("-s") - 1 : rule.index("-s") + 2], ["!", "-s", p["guest"] + "/32"])
            self.assertEqual(rule[rule.index("-d") - 1 : rule.index("-d") + 2], ["!", "-d", p["system_dns"] + "/32"])
            self.assertEqual(rule[-1], "RETURN")
            # Before marking, so such packets are never marked or redirected.
            self.assertLess(body.index(rule), next(i for i, r in enumerate(body) if "CONNMARK" in r))
        # Left unmarked, the target's own containers meet the per-network
        # drop in the bridge gate (decision 24); FORWARD only enters the gate.
        self.assertEqual([rule[-1] for rule in guards if rule[1] == "FORWARD"], ["WPM2F_12345678"])
        self.assertIn("WPM2FB_12345678", [rule[-1] for rule in guards if rule[1] == "WPM2F_12345678"])
        # The installed shape is still recognized as this instance's own.
        kernel.inspect_firewall(p, snapshot(p), True)

    def test_changed_identity_can_only_attest_independently_proved_absence(self):
        for reason in ("boot_changed", "cgroup_namespace_changed", "cgroup_root_changed", "guest_address_changed"):
            p = comprehensive_plan()
            other = copy.deepcopy(p)
            other["cookie"] += 1
            foreign = snapshot(other)
            foreign["filter"]["rules"][0].extend(["--unrelated-shape", "unreachable"])
            value = self.observe(p, [foreign, ipv6_snapshot(other)], identity_error=reason)
            self.assertEqual(value, {"identity_matches": False, "rules_present": False, "rules_complete": False, "mappings_present": False, "unproven_mappings": 0, "forward_displaced": False, "rules_bound": True})
            with self.subTest(reason=reason), self.assertRaises(kernel.Failure):
                self.observe(p, [snapshot(p), ipv6_snapshot(p)], identity_error=reason)
        # Any other drift is handled the same way: it can attest absence only.
        value = self.observe(plan(), [{}], identity_error="workload_outside_distro_cgroup")
        self.assertEqual(value, {"identity_matches": False, "rules_present": False, "rules_complete": False, "mappings_present": False, "unproven_mappings": 0, "forward_displaced": False, "rules_bound": True})
        with self.assertRaisesRegex(kernel.Failure, "stale_identity_has_owned_artifacts: workload_outside_distro_cgroup"):
            self.observe(plan(), [snapshot(plan())], identity_error="workload_outside_distro_cgroup")

    def test_pending_install_and_corrupt_owned_shapes_never_attest_clean(self):
        with self.assertRaisesRegex(kernel.Failure, "install_grant_pending"):
            self.observe(plan(), [{}], pending=True)
        tables = snapshot()
        tables["nat"]["rules"][0].extend(["--unrecognized", "option"])
        with self.assertRaises(kernel.Failure):
            self.observe(plan(), [tables])
        p = comprehensive_plan()
        v6 = ipv6_snapshot(p)
        v6["filter"]["rules"].append(copy.deepcopy(v6["filter"]["rules"][0]))
        with self.assertRaises(kernel.Failure):
            self.observe(p, [snapshot(p), v6])

    def test_both_families_and_connmark_proofs_precede_every_network_delete(self):
        p = comprehensive_plan()
        corrupt_v6 = ipv6_snapshot(p)
        corrupt_v6["filter"]["rules"][0].remove("!")
        corrupt_mapping = comprehensive_entry()
        corrupt_mapping["reply"] = (17, "172.28.80.1", 9999, p["guest"], 45000)
        operation = request(p)
        operation["operation"] = "remove"
        # A corrupt owned rule shape still blocks every delete: the rules
        # themselves could not be told apart from another instance's.
        with patch.object(kernel, "guest_lock"), patch.object(kernel, "guard"), patch.object(kernel, "grant") as grant, patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=[snapshot(p), corrupt_v6]), patch.object(kernel, "transaction") as transact:
            conntrack.return_value.dump.return_value = []
            with self.assertRaises(kernel.Failure):
                kernel.execute(operation)
            grant.assert_called_once_with(p, "revoke")
            transact.assert_not_called()
            conntrack.return_value.delete.assert_not_called()

    def test_unprovable_marked_mappings_do_not_block_removing_the_rules(self):
        # Decision 20: an unprovable or foreign-family entry with this mark is
        # counted and left alone; the exact-tagged rules are still removed.
        p = comprehensive_plan()
        corrupt_mapping = comprehensive_entry()
        corrupt_mapping["reply"] = (17, "172.28.80.1", 9999, p["guest"], 45000)
        operation = request(p)
        operation["operation"] = "remove"
        for mappings, v6_mappings in (([corrupt_mapping], []), ([], [{"mark": p["cookie"]}])):
            with self.subTest(mappings=mappings, v6_mappings=v6_mappings), patch.object(kernel, "guest_lock"), patch.object(kernel, "guard"), patch.object(kernel, "grant"), patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=[snapshot(p), ipv6_snapshot(p), {}, {}]), patch.object(kernel, "transaction") as transact:
                conntrack.return_value.dump.side_effect = lambda ipv6=False: v6_mappings if ipv6 else mappings
                result = kernel.execute(operation)
                self.assertEqual(result, {"ok": True, "operation": "remove", "unproven_mappings": 1})
                self.assertTrue(transact.call_args_list)
                self.assertTrue(all(rule[0] in ("-D", "-X") for call in transact.call_args_list for rule in call.args[1]))
                conntrack.return_value.delete.assert_not_called()

    def test_ambiguous_original_or_reply_mapping_is_never_owned(self):
        first = entry()
        for second in (entry(identifier=2), entry(origin=1, identifier=2)):
            with self.subTest(second=second), self.assertRaises(kernel.Failure):
                kernel.owned_entries(plan(), [first, second])

    def test_ipv6_dump_is_explicit_and_same_cookie_ipv6_is_never_deleted(self):
        ct = object.__new__(kernel.Conntrack)
        with patch.object(ct, "request", return_value=[]) as send:
            self.assertEqual(ct.dump(ipv6=True), [])
        send.assert_called_once_with(kernel.CT_GET, kernel.ROOT | kernel.MATCH, ipv6=True)
        # Counted as unprovable, never deleted (`observe` asserts no delete).
        value = self.observe(comprehensive_plan(), [{}, {}], ipv6_entries=[{"mark": plan()["cookie"]}])
        self.assertEqual(value["unproven_mappings"], 1)
        self.assertFalse(value["mappings_present"])


DOCKER_NETWORKS = [
    # Shaped like a real `GET /networks` answer; names and ids are made up.
    {"Name": "bridge", "Id": "09a063a82840" + "1" * 52, "Driver": "bridge", "Options": {"com.docker.network.bridge.name": "docker0"}, "IPAM": {"Driver": "default", "Config": [{"Subnet": "172.17.0.0/16", "Gateway": "172.17.0.1"}]}},
    {"Name": "shop", "Id": "acc14c99a879" + "2" * 52, "Driver": "bridge", "Options": {}, "IPAM": {"Driver": "default", "Config": [{"Subnet": "172.18.0.0/16", "Gateway": "172.18.0.1"}, {"Subnet": "fd00:db8:18::/64"}]}},
    {"Name": "host", "Id": "3161673e190f" + "3" * 52, "Driver": "host", "Options": {}, "IPAM": {"Driver": "default", "Config": None}},
    {"Name": "none", "Id": "c335aa371a37" + "4" * 52, "Driver": "null", "Options": {}, "IPAM": {"Driver": "default", "Config": None}},
    # A bridge network whose interface is not in this network stack.
    {"Name": "elsewhere", "Id": "ffeeddccbbaa" + "5" * 52, "Driver": "bridge", "Options": {}, "IPAM": {"Config": [{"Subnet": "172.19.0.0/16"}]}},
    {"Name": "odd", "Id": "not-an-id", "Driver": "bridge", "Options": {}, "IPAM": {"Config": [{"Subnet": "172.20.0.0/16"}]}},
    {"Name": "evil", "Id": "aaaaaaaaaaaa" + "6" * 52, "Driver": "bridge", "Options": {"com.docker.network.bridge.name": "eth0"}, "IPAM": {"Config": [{"Subnet": "172.21.0.0/16"}]}},
]
PRESENT = {"docker0", "br-acc14c99a879", "eth0"}
WANTED = {"docker0": {"v4": ["172.17.0.0/16"], "v6": []}, "br-acc14c99a879": {"v4": ["172.18.0.0/16"], "v6": ["fd00:db8:18::/64"]}}


def with_networks(tables, p, networks, ipv6=False):
    """`tables` with the per-network rules for `networks` in their chains,
    ahead of each chain's final RETURN, as a sync would leave them."""
    nat, filtered = kernel.network_rules(p, networks, ipv6)
    for table, rules in (("nat", nat), *kernel.split_guards(filtered).items()):
        if not rules:
            continue
        existing = tables[table]["rules"]
        for rule in rules:
            last = max(index for index, current in enumerate(existing) if current[1] == rule[1])
            existing.insert(last, copy.deepcopy(rule))
    return tables


class ContainerNetworkTests(unittest.TestCase):
    def test_docker_networks_are_asked_only_while_dockerd_runs(self):
        with patch.object(kernel, "dockerd_running", return_value=False), patch.object(kernel, "docker_request") as ask:
            self.assertIsNone(kernel.docker_networks())
        ask.assert_not_called()
        with patch.object(kernel, "dockerd_running", return_value=True), patch.object(kernel.os.path, "exists", return_value=True), patch.object(kernel, "docker_request", return_value=DOCKER_NETWORKS), patch.object(kernel.os.path, "isdir", side_effect=lambda path: path.rsplit("/", 1)[-1] in PRESENT):
            self.assertEqual(kernel.docker_networks(), WANTED)
        with patch.object(kernel, "dockerd_running", return_value=True), patch.object(kernel.os.path, "exists", return_value=True), patch.object(kernel, "docker_request", side_effect=OSError("refused")):
            with self.assertRaisesRegex(kernel.Failure, "docker_networks_unavailable"):
                kernel.docker_networks()
        with patch.object(kernel, "dockerd_running", return_value=True), patch.object(kernel.os.path, "exists", return_value=False):
            with self.assertRaisesRegex(kernel.Failure, "docker_socket_missing"):
                kernel.docker_networks()

    def test_dockerd_counts_only_by_name_in_this_network_stack(self):
        here, elsewhere = "net:[4026531833]", "net:[4026532201]"
        stacks = {"self": here}

        def process(proc, pid, name, netns):
            os.mkdir(os.path.join(proc, pid))
            with open(os.path.join(proc, pid, "comm"), "w") as handle:
                handle.write(name + "\n")
            stacks[pid] = netns

        def netns(pid):
            if pid not in stacks:
                raise FileNotFoundError(pid)
            return stacks[pid]

        with tempfile.TemporaryDirectory() as proc:
            for pid, name in (("1", "systemd"), ("42", "containerd")):
                process(proc, pid, name, here)
            os.mkdir(os.path.join(proc, "self"))
            with open(os.path.join(proc, "self", "comm"), "w") as handle:
                handle.write("dockerd\n")
            self.assertFalse(kernel.dockerd_running(proc, netns))
            # Rootless Docker or Docker in a container: its own network stack,
            # no bridges here, its containers leave as the target's processes.
            process(proc, "66", "dockerd", elsewhere)
            self.assertFalse(kernel.dockerd_running(proc, netns))
            process(proc, "77", "dockerd", here)
            self.assertTrue(kernel.dockerd_running(proc, netns))
            # A process gone between listing and reading is skipped.
            os.mkdir(os.path.join(proc, "88"))
            with open(os.path.join(proc, "88", "comm"), "w") as handle:
                handle.write("dockerd\n")
            del stacks["77"]
            self.assertFalse(kernel.dockerd_running(proc, netns))
            # The default reads /proc/<pid>/ns/net.
            same = {os.path.join(proc, pid, "ns", "net") for pid in ("self", "77")}
            with patch.object(kernel.os, "readlink", side_effect=lambda path: here if path in same else elsewhere) as readlink:
                stacks["77"] = here
                self.assertTrue(kernel.dockerd_running(proc))
            self.assertIn(os.path.join(proc, "self", "ns", "net"), [call.args[0] for call in readlink.call_args_list])

    def test_only_bridge_networks_with_an_interface_here_count(self):
        self.assertEqual(kernel.parse_docker_networks(DOCKER_NETWORKS, lambda name: name in PRESENT), WANTED)
        with self.assertRaises(kernel.Failure):
            kernel.parse_docker_networks({"not": "a list"}, lambda name: True)

    def test_network_rules_keep_subnets_local_redirect_the_rest_and_drop_leftovers(self):
        p = comprehensive_plan()
        nat, filtered = kernel.network_rules(p, {"docker0": WANTED["docker0"]})
        self.assertEqual([(rule[1], rule[rule.index("-i") + 1], rule[-1]) for rule in nat], [("WPM2B_12345678", "docker0", "RETURN"), ("WPM2B_12345678", "docker0", "WPM2_12345678")])
        self.assertEqual(nat[0][nat[0].index("-d") + 1], "172.17.0.0/16")
        gate = [rule for rule in filtered if rule[1] == "WPM2FB_12345678"]
        self.assertEqual([rule[-1] for rule in gate], ["RETURN"] * 3 + ["DROP"])
        self.assertEqual([rule[rule.index("-d") + 1] for rule in gate[:-1]], ["172.17.0.0/16", "224.0.0.0/4", "255.255.255.255/32"])
        # Link-local IPv4 (169.254.169.254 and the like) is routable: dropped
        # as for the target's own processes, never let through.
        self.assertFalse(any(ipaddress.ip_address("169.254.169.254") in ipaddress.ip_network(scope) for scope in kernel.LOCAL_SCOPES["v4"]))
        # The target's own traffic to the network, through its bridge only,
        # passes the local guard (M19): the host, docker-proxy behind a
        # published port. Nothing else is added to the guard.
        guard = [rule for rule in filtered if rule[1] == "WPM2G_12345678"]
        self.assertEqual(guard, [["-A", "WPM2G_12345678", "-o", "docker0", "-d", "172.17.0.0/16", "-m", "comment", "--comment", kernel.network_tag(p), "-j", "RETURN"]])
        self.assertEqual(len(filtered), len(gate) + len(guard))
        # IPv6 block mode: no redirection, only the drop of what is not
        # local; the target's own IPv6 stays dropped on OUTPUT itself.
        nat6, filtered6 = kernel.network_rules(p, WANTED, ipv6=True)
        self.assertEqual(nat6, [])
        self.assertEqual([rule[-1] for rule in filtered6].count("DROP"), 2)
        self.assertIn("fd00:db8:18::/64", [token for rule in filtered6 for token in rule])
        self.assertFalse([rule for rule in filtered6 if "-o" in rule])
        # Managed IPv6: the IPv6 guard gets the same rule for IPv6 subnets.
        managed = dict(p, ipv6={"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"})
        _, filtered6m = kernel.network_rules(managed, WANTED, ipv6=True)
        self.assertEqual([(rule[1], rule[3], rule[5]) for rule in filtered6m if "-o" in rule], [("WPM2VG_12345678", "br-acc14c99a879", "fd00:db8:18::/64")])
        for rule in nat + filtered + filtered6:
            name = rule[rule.index("-i" if "-i" in rule else "-o") + 1]
            self.assertEqual(kernel.network_rule_owner(p, rule, rule in filtered6), name)
        for rule in filtered6m:
            self.assertIsNotNone(kernel.network_rule_owner(managed, rule, True))

    def test_while_no_dockerd_runs_covered_networks_stay_while_their_bridge_exists(self):
        # A stopped or restarting dockerd (live-restore keeps containers up)
        # must not turn a covered bridge into a direct path.
        p = comprehensive_plan()
        _, rules = kernel.inspect_firewall(p, with_networks(snapshot(p), p, WANTED), True)
        _, rules6 = kernel.inspect_firewall(p, with_networks(ipv6_snapshot(p), p, WANTED, ipv6=True), True, ipv6=True)
        with patch.object(kernel, "docker_networks", return_value=None):
            self.assertEqual(kernel.wanted_networks(p, rules, rules6, exists=lambda name: True), WANTED)
            kept = kernel.wanted_networks(p, rules, rules6, exists=lambda name: name == "docker0")
        self.assertEqual(kept, {"docker0": WANTED["docker0"]})
        self.assertEqual(kernel.network_changes(p, rules, WANTED), ([], []))
        with patch.object(kernel, "docker_networks", return_value={}):
            self.assertEqual(kernel.wanted_networks(p, rules, rules6, exists=lambda name: True), {})

    def test_installed_network_rules_are_owned_but_not_part_of_completeness(self):
        p = comprehensive_plan()
        tables = with_networks(snapshot(p), p, WANTED)
        tables6 = with_networks(ipv6_snapshot(p), p, WANTED, ipv6=True)
        present, rules = kernel.inspect_firewall(p, tables, True)
        _, rules6 = kernel.inspect_firewall(p, tables6, True, ipv6=True)
        self.assertTrue(kernel.rules_complete(p, present, rules, rules6))
        self.assertEqual(sorted(kernel.installed_networks(p, rules)), sorted(WANTED))
        self.assertEqual(kernel.network_changes(p, rules, WANTED), ([], []))
        self.assertEqual(kernel.network_changes(p, rules6, WANTED, ipv6=True), ([], []))
        # Anything else carrying the per-network tag is refused.
        tag = kernel.network_tag(p)
        strays = [
            ["-A", "WPM2B_12345678", "-i", "eth0", "-m", "comment", "--comment", tag, "-j", "WPM2_12345678"],
            ["-A", "WPM2F_12345678", "-i", "docker0", "-m", "comment", "--comment", tag, "-j", "DROP"],
            ["-A", "WPM2FB_12345678", "-i", "docker0", "-d", "fd00::/8", "-m", "comment", "--comment", tag, "-j", "RETURN"],
            ["-A", "WPM2B_12345678", "-i", "docker0", "-m", "comment", "--comment", tag, "-j", "ACCEPT"],
            ["-A", "WPM2B_12345678", "-i", "docker0", "-p", "tcp", "-m", "comment", "--comment", tag, "-j", "WPM2_12345678"],
            # The guard rule only ever pairs this network's bridge with its subnet.
            ["-A", "WPM2G_12345678", "-o", "docker0", "-m", "comment", "--comment", tag, "-j", "RETURN"],
            ["-A", "WPM2G_12345678", "-o", "eth0", "-d", "172.17.0.0/16", "-m", "comment", "--comment", tag, "-j", "RETURN"],
            ["-A", "WPM2G_12345678", "-o", "docker0", "-d", "224.0.0.0/4", "-m", "comment", "--comment", tag, "-j", "RETURN"],
            ["-A", "WPM2G_12345678", "-o", "docker0", "-d", "172.17.0.0/16", "-m", "comment", "--comment", tag, "-j", "ACCEPT"],
            ["-A", "WPM2G_12345678", "-i", "docker0", "-o", "docker0", "-d", "172.17.0.0/16", "-m", "comment", "--comment", tag, "-j", "RETURN"],
            ["-A", "WPM2FB_12345678", "-o", "docker0", "-d", "172.17.0.0/16", "-m", "comment", "--comment", tag, "-j", "RETURN"],
        ]
        for stray in strays:
            with self.subTest(stray=stray):
                broken = snapshot(p)
                table = "nat" if stray[1].startswith("WPM2B") else "filter"
                broken[table]["rules"].insert(0, stray)
                with self.assertRaisesRegex(kernel.Failure, "foreign_instance_rule"):
                    kernel.inspect_firewall(p, broken, True)

    def test_a_stop_removes_the_network_rules_with_the_rest(self):
        p = comprehensive_plan()
        tables = with_networks(snapshot(p), p, WANTED)
        tables6 = with_networks(ipv6_snapshot(p), p, WANTED, ipv6=True)
        operation = request(p)
        operation["operation"] = "remove"
        with patch.object(kernel, "guest_lock"), patch.object(kernel, "grant"), patch.object(kernel, "guard"), patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=[tables, tables6, {}, {}]), patch.object(kernel, "transaction") as transact:
            conntrack.return_value.dump.return_value = []
            kernel.execute(operation)
        lines = [line for call in transact.call_args_list for line in call.args[1]]
        deleted = sum(1 for line in lines if line[0] == "-D")
        self.assertEqual(deleted, sum(len(table["rules"]) for both in (tables, tables6) for table in both.values()))

    def sync(self, p, tables, tables6, wanted, guard_error=None):
        operation = request(p)
        operation["operation"] = "sync_networks"
        failure = kernel.Failure(guard_error) if guard_error else None
        with patch.object(kernel, "guest_lock"), patch.object(kernel, "guard", side_effect=failure), patch.object(kernel, "Conntrack"), patch.object(kernel, "firewall", side_effect=[tables, tables6]), patch.object(kernel, "docker_networks", return_value=wanted), patch.object(kernel, "transaction") as transact:
            result = kernel.execute(operation)
        return result, [(call.args[0], call.kwargs.get("ipv6", False), call.args[1]) for call in transact.call_args_list]

    def test_sync_adds_new_networks_and_removes_gone_ones_in_a_safe_order(self):
        p = comprehensive_plan()
        old = {"docker0": WANTED["docker0"]}
        new = {"br-acc14c99a879": WANTED["br-acc14c99a879"]}
        tables = with_networks(snapshot(p), p, old)
        tables6 = with_networks(ipv6_snapshot(p), p, old, ipv6=True)
        result, calls = self.sync(p, tables, tables6, new)
        self.assertEqual(result["synced"], {"current": ["br-acc14c99a879"], "added": ["br-acc14c99a879"], "removed": ["docker0"]})
        # Removals: redirection (nat) before the drops; additions: drops first.
        self.assertEqual([(table, ipv6, lines[0][0]) for table, ipv6, lines in calls], [("nat", False, "-D"), ("filter", False, "-D"), ("mangle", False, "-D"), ("mangle", True, "-D"), ("filter", False, "-I"), ("mangle", False, "-I"), ("mangle", True, "-I"), ("nat", False, "-I")])
        removed = [line for _, _, lines in calls for line in lines if line[0] == "-D"]
        self.assertTrue(all("docker0" in line for line in removed))
        for table, ipv6, lines in calls:
            if lines[0][0] != "-I":
                continue
            # Inserted at the top in reverse, so they end up in rule order.
            final = [["-A", line[1], *line[3:]] for line in reversed(lines)]
            nat, filtered = kernel.network_rules(p, new, ipv6)
            expected = nat if table == "nat" else kernel.split_guards(filtered)[table]
            self.assertEqual(final, expected)
        # Nothing to do when the rules already match.
        result, calls = self.sync(p, tables, tables6, old)
        self.assertEqual((result["synced"]["added"], result["synced"]["removed"], calls), ([], [], []))

    def installed(self, p, networks):
        """The tables `install_rules` leaves behind, applied as iptables
        would apply each restore document in order."""
        state = {"v4": {}, "v6": {}}

        def apply(table, lines, test=False, ipv6=False, backend="nft"):
            if test:
                return
            current = state["v6" if ipv6 else "v4"].setdefault(table, {"chains": {"OUTPUT": "ACCEPT"}, "rules": []})
            rules = current["rules"]
            for line in lines:
                if line[0] == "-N":
                    self.assertNotIn(line[1], current["chains"])
                    current["chains"][line[1]] = "-"
                elif line[0] == "-A":
                    rules.append(list(line))
                elif line[0] == "-I":
                    self.assertEqual(line[2], "1")
                    first = next((index for index, rule in enumerate(rules) if rule[1] == line[1]), len(rules))
                    rules.insert(first, ["-A", line[1], *line[3:]])
                else:
                    self.fail(line)

        with patch.object(kernel, "transaction", side_effect=apply) as transact:
            kernel.install_rules(p, networks=networks)
        return state, [(call.args[0], call.kwargs.get("ipv6", False)) for call in transact.call_args_list]

    def test_install_commits_the_network_rules_with_the_base_rules(self):
        for ipv6 in (None, {"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"}):
            with self.subTest(managed_ipv6=ipv6 is not None):
                p = comprehensive_plan()
                p["ipv6"] = ipv6
                state, order = self.installed(p, WANTED)
                # Still drops before redirection, IPv4 nat last.
                self.assertEqual(order[0], ("filter", False))
                self.assertEqual(order[-1], ("nat", False))
                present, rules = kernel.inspect_firewall(p, state["v4"], True)
                _, ipv6_rules = kernel.inspect_firewall(p, state["v6"], True, ipv6=True)
                self.assertTrue(kernel.rules_complete(p, present, rules, ipv6_rules))
                # Exactly what a sync right after would want: nothing to add or remove.
                self.assertEqual(kernel.network_changes(p, rules, WANTED), ([], []))
                self.assertEqual(kernel.network_changes(p, ipv6_rules, WANTED, ipv6=True), ([], []))
                self.assertEqual(sorted(kernel.installed_networks(p, rules)), sorted(WANTED))
                # And the same rules a base install followed by a sync leaves.
                base, _ = self.installed(p, None)
                self.assertEqual(kernel.installed_networks(p, {table: base["v4"][table]["rules"] for table in base["v4"]}), {})
                for family in ("v4", "v6"):
                    for table in state[family]:
                        merged = with_networks(copy.deepcopy(base[family]), p, WANTED, ipv6=family == "v6")
                        self.assertEqual(sorted(map(kernel.rule_key, state[family][table]["rules"])), sorted(map(kernel.rule_key, merged[table]["rules"])), (family, table))

    def test_install_without_networks_commits_only_the_base_rules(self):
        p = comprehensive_plan()
        for networks in (None, {}):
            with self.subTest(networks=networks):
                state, _ = self.installed(p, networks)
                expected = snapshot(p)
                self.assertEqual(sorted(map(kernel.rule_key, state["v4"]["nat"]["rules"])), sorted(map(kernel.rule_key, expected["nat"]["rules"])))
                self.assertEqual(sorted(map(kernel.rule_key, state["v4"]["filter"]["rules"])), sorted(map(kernel.rule_key, expected["filter"]["rules"])))

    def test_install_retries_a_dockerd_that_is_not_answering_yet(self):
        p = comprehensive_plan()
        pauses = []
        failure = kernel.Failure("docker_networks_unavailable")
        with patch.object(kernel, "docker_networks", side_effect=[failure, kernel.Failure("docker_socket_missing"), WANTED]) as ask:
            self.assertEqual(kernel.install_networks(p, pause=pauses.append), WANTED)
        self.assertEqual(ask.call_count, 3)
        self.assertEqual(pauses, [kernel.INSTALL_NETWORK_PAUSE] * 2)
        # Gives up after a bounded number of tries: base rules only, the
        # following sync reports the failure.
        pauses.clear()
        with patch.object(kernel, "docker_networks", side_effect=failure) as ask:
            self.assertIsNone(kernel.install_networks(p, pause=pauses.append))
        self.assertEqual(ask.call_count, kernel.INSTALL_NETWORK_TRIES)
        self.assertLessEqual(kernel.INSTALL_NETWORK_TRIES * 3 + len(pauses) * kernel.INSTALL_NETWORK_PAUSE, 20)
        # No dockerd: nothing to cover, no retry.
        with patch.object(kernel, "docker_networks", return_value=None) as ask:
            self.assertEqual(kernel.install_networks(p, pause=pauses.append), {})
        self.assertEqual(ask.call_count, 1)
        # Scoped mode never reads Docker.
        with patch.object(kernel, "docker_networks") as ask:
            self.assertEqual(kernel.install_networks(plan()), {})
        ask.assert_not_called()

    def test_only_the_install_itself_reads_the_networks(self):
        p = comprehensive_plan()
        for operation_name, reads in (("precheck", False), ("install", True)):
            with self.subTest(operation=operation_name):
                operation = request(p)
                operation["operation"] = operation_name
                with patch.object(kernel, "guest_lock"), patch.object(kernel, "guard"), patch.object(kernel, "grant"), patch.object(kernel, "Conntrack"), patch.object(kernel, "firewall", return_value={}), patch.object(kernel, "inspect_firewall"), patch.object(kernel, "inspect_mappings", return_value=[]), patch.object(kernel, "inspect_ipv6_mappings", return_value=[]), patch.object(kernel, "install_networks", return_value=WANTED) as ask, patch.object(kernel, "install_rules") as install:
                    kernel.execute(operation)
                self.assertEqual(ask.called, reads)
                expected = WANTED if reads else None
                self.assertTrue(all(call.kwargs.get("networks") == expected for call in install.call_args_list))
                self.assertEqual([call.kwargs.get("test", False) for call in install.call_args_list], [True, False] if reads else [True])

    def test_sync_extends_only_a_complete_takeover_of_this_identity(self):
        p = comprehensive_plan()
        partial = snapshot(p)
        del partial["nat"]
        with self.assertRaisesRegex(kernel.Failure, "network_sync_without_complete_rules"):
            self.sync(p, partial, ipv6_snapshot(p), WANTED)
        with self.assertRaisesRegex(kernel.Failure, "boot_changed"):
            self.sync(p, snapshot(p), ipv6_snapshot(p), WANTED, guard_error="boot_changed")

    def test_inspect_reports_network_drift_without_changing_anything(self):
        p = comprehensive_plan()
        operation = request(p)
        operation["operation"] = "inspect"
        tables = with_networks(snapshot(p), p, {"docker0": WANTED["docker0"]})
        tables6 = with_networks(ipv6_snapshot(p), p, {"docker0": WANTED["docker0"]}, ipv6=True)
        for wanted, expected in (({"docker0": WANTED["docker0"]}, True), (WANTED, False), ({}, False)):
            with self.subTest(wanted=sorted(wanted)), patch.object(kernel, "guest_lock"), patch.object(kernel, "guard"), patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=[copy.deepcopy(tables), copy.deepcopy(tables6)]), patch.object(kernel, "docker_networks", return_value=wanted), patch.object(kernel, "transaction") as transact:
                conntrack.return_value.dump.return_value = []
                result = kernel.execute(operation)
                transact.assert_not_called()
            self.assertEqual(result["networks"], {"installed": ["docker0"], "wanted": sorted(wanted), "in_sync": expected, "error": None})
        with patch.object(kernel, "guest_lock"), patch.object(kernel, "guard"), patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=[copy.deepcopy(tables), copy.deepcopy(tables6)]), patch.object(kernel, "docker_networks", side_effect=kernel.Failure("docker_networks_unavailable")):
            conntrack.return_value.dump.return_value = []
            result = kernel.execute(operation)
        self.assertEqual(result["networks"]["error"], "docker_networks_unavailable")
        self.assertIsNone(result["networks"]["in_sync"])


class GrantTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="proxy-kernel-grant-test-")
        self.addCleanup(directory.cleanup)
        self.directory = os.path.join(directory.name, "grants")
        location = patch.object(kernel, "GRANT_DIRECTORY", self.directory)
        location.start()
        self.addCleanup(location.stop)
        clock = patch.object(kernel.time, "time", return_value=1000)
        self.clock = clock.start()
        self.addCleanup(clock.stop)

    def filename(self, p=None):
        return os.path.join(self.directory, kernel.plan_digest(p or plan()) + ".json")

    def test_precheck_window_uses_guest_clock_and_transit_does_not_renew_it(self):
        req = request()
        with patch.object(kernel, "guest_lock"), patch.object(kernel, "guard"), patch.object(kernel, "Conntrack"), patch.object(kernel, "firewall", return_value={}), patch.object(kernel, "inspect_mappings", return_value=[]), patch.object(kernel, "install_rules"):
            window = kernel.execute(req)["grant_deadline"]
        self.assertEqual(window, 1030)
        self.clock.return_value = 1029
        kernel.grant(req["plan"], "arm", window)
        self.clock.return_value = 1030
        with self.assertRaisesRegex(kernel.Failure, "expired"):
            kernel.grant(req["plan"], "consume")

    def test_install_needs_exact_unexpired_once_only_ticket(self):
        p = plan()
        with self.assertRaises(kernel.Failure):
            kernel.grant(p, "consume")
        kernel.grant(p, "arm", 1030)
        self.assertTrue(kernel.grant_pending(p))
        changed = copy.deepcopy(p)
        changed["ingress"] = "172.28.80.1:43780"
        with self.assertRaises(kernel.Failure):
            kernel.grant(changed, "consume")
        kernel.grant(p, "consume")
        self.assertFalse(kernel.grant_pending(p))
        with self.assertRaises(kernel.Failure):
            kernel.grant(p, "consume")
        kernel.grant(p, "revoke")
        self.assertFalse(os.path.exists(self.directory))
        with self.assertRaises(kernel.Failure):
            kernel.grant(p, "consume")

    def test_uncertain_arm_is_revoked_and_bounded_marker_is_later_collected(self):
        p = plan()
        kernel.grant(p, "revoke")
        self.assertFalse(kernel.grant_pending(p))
        with self.assertRaises(kernel.Failure):
            kernel.grant(p, "arm", 1030)
        with self.assertRaises(kernel.Failure):
            kernel.grant(p, "consume")
        self.clock.return_value = 1031
        with self.assertRaises(kernel.Failure):
            kernel.grant(p, "arm", 1030)
        other = copy.deepcopy(p)
        other["cookie"] += 1
        kernel.grant(other, "arm", 1061)
        self.assertFalse(os.path.exists(self.filename(p)))
        self.assertTrue(os.path.exists(self.filename(other)))

    def test_expired_observation_is_read_only_and_cannot_authorize_install(self):
        p = plan()
        kernel.grant(p, "arm", 1030)
        self.clock.return_value = 1031
        self.assertFalse(kernel.grant_pending(p))
        self.assertTrue(os.path.exists(self.filename()))
        with self.assertRaises(kernel.Failure):
            kernel.grant(p, "consume")
        kernel.grant(p, "revoke")
        self.assertFalse(os.path.exists(self.directory))

    def test_interrupted_ticket_write_is_recoverably_revoked(self):
        p = plan()
        kernel.grant(p, "arm", 1030)
        with open(self.filename(), "w", encoding="ascii") as handle:
            handle.write("{interrupted")
        with self.assertRaises(ValueError):
            kernel.grant(p, "consume")
        kernel.grant(p, "revoke")
        self.assertFalse(kernel.grant_pending(p))
        with open(self.filename(), encoding="ascii") as handle:
            self.assertEqual(json.load(handle), {"state": "revoked", "deadline": 1030})

    def test_ticket_symlink_never_modifies_its_target(self):
        os.mkdir(self.directory, 0o700)
        target = self.directory + "-unrelated"
        with open(target, "w", encoding="ascii") as handle:
            handle.write("untouched")
        self.addCleanup(os.unlink, target)
        os.symlink(target, self.filename())
        for action in ("consume", "revoke"):
            with self.subTest(action=action), self.assertRaises(OSError):
                kernel.grant(plan(), action)
        with open(target, encoding="ascii") as handle:
            self.assertEqual(handle.read(), "untouched")

    def test_guest_lock_uses_existing_directory_exclusively_without_creation(self):
        info = type("Info", (), {"st_uid": 0, "st_mode": 0o40755})()
        with patch.object(kernel.os, "geteuid", return_value=0), patch.object(kernel.os, "open", return_value=9) as opened, patch.object(kernel.os, "fstat", return_value=info), patch.object(kernel.fcntl, "flock") as flock, patch.object(kernel.os, "close") as closed:
            with kernel.guest_lock():
                flock.assert_called_once_with(9, kernel.fcntl.LOCK_EX)
                closed.assert_not_called()
            self.assertEqual(opened.call_args.args[0], "/run")
            self.assertFalse(opened.call_args.args[1] & os.O_CREAT)
            closed.assert_called_once_with(9)

    def test_install_and_remove_are_locked_before_grant_or_kernel_access(self):
        for operation in ("install", "remove"):
            value = request()
            value["operation"] = operation
            with patch.object(kernel, "guest_lock") as lock, patch.object(kernel, "guard") as guard, patch.object(kernel, "grant") as grant, patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", return_value={}), patch.object(kernel, "install_rules"), patch.object(kernel, "transaction"):
                conntrack.return_value.dump.return_value = []
                grant.side_effect = lambda *args: lock.return_value.__enter__.assert_called_once()
                kernel.execute(value)
                guard.assert_called_once_with(value["plan"], check_resolver=operation != "remove", write_tools=True)
                grant.assert_called_once_with(value["plan"], "consume" if operation == "install" else "revoke")


if __name__ == "__main__":
    unittest.main()
