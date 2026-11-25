"""Pure guest-kernel boundary tests; no guest or network operation is performed."""

import copy
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


def snapshot(p=None):
    p = p or plan()
    chain, _, hooks, body, guards = kernel.artifacts(p)
    tables = {
        "nat": {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(hooks + body)},
        "filter": {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(guards)},
    }
    return declare_chains(tables, p)


def ipv6_snapshot(p):
    tables = {"filter": {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(kernel.ipv6_guards(p))}}
    return declare_chains(tables, p, ipv6=True)


def ipv6_full_snapshot(p):
    chain, guard, _, hooks, body, guards = kernel.ipv6_artifacts(p)
    tables = {
        "nat": {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(hooks + body)},
        "filter": {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(guards)},
    }
    return declare_chains(tables, p, ipv6=True)


def legacy_snapshot(p, ipv6=False):
    """What an older version installed: PREROUTING ! -i eth0 straight into the
    redirect chain, and accepts plus a global drop on FORWARD."""
    if ipv6:
        tables = ipv6_full_snapshot(p) if p.get("ipv6") is not None else ipv6_snapshot(p)
    else:
        tables = snapshot(p)
    cookie = f"{p['cookie']:08x}"
    newer = {prefix + cookie for prefix in ("WPM2B_", "WPM2F_", "WPM2FB_", "WPM2VB_", "WPM2VF_", "WPM2VFB_")}
    legacy = kernel.legacy_rules(p, ipv6)
    for name, table in tables.items():
        table["rules"] = [rule for rule in table["rules"] if rule[1] not in newer and rule[1] not in ("PREROUTING", "FORWARD")]
        table["rules"] += [rule for rule in legacy if ("nat" if rule[1] == "PREROUTING" else "filter") == name]
        for chain_name in newer:
            table["chains"].pop(chain_name, None)
    return tables


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
        for p in (comprehensive_plan(), dict(comprehensive_plan(), ipv6={"guest": "2001:db8:1::2", "ingress": "[fe80::1%2]:43771"})):
            with self.subTest(ipv6=p.get("ipv6") is not None):
                old, old6 = legacy_snapshot(p), legacy_snapshot(p, ipv6=True)
                present, rules = kernel.inspect_firewall(p, old, True)
                _, ipv6_rules = kernel.inspect_firewall(p, old6, True, ipv6=True)
                self.assertTrue(present)
                self.assertFalse(kernel.rules_complete(p, present, rules, ipv6_rules))
                # Not an install target either: nothing of this instance may exist.
                with self.assertRaises(kernel.Failure):
                    kernel.inspect_firewall(p, old, False)
                operation = request(p)
                operation["operation"] = "remove"
                with patch.object(kernel, "guest_lock"), patch.object(kernel, "grant"), patch.object(kernel, "guard"), patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=[old, old6, {}, {}]), patch.object(kernel, "transaction") as transact:
                    conntrack.return_value.dump.return_value = []
                    kernel.execute(operation)
                lines = [line for call in transact.call_args_list for line in call.args[1]]
                self.assertTrue(all(line[0] in ("-D", "-X") for line in lines))
                removed = {line[1] for line in lines if line[0] == "-X"}
                expected = {"WPM2_12345678", "WPM2G_12345678"}
                if p.get("ipv6") is not None:
                    expected |= {"WPM2V_12345678", "WPM2VG_12345678"}
                self.assertEqual(removed, expected)
                deleted = sum(1 for line in lines if line[0] == "-D")
                self.assertEqual(deleted, sum(len(table["rules"]) for tables in (old, old6) for table in tables.values()))

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
        self.assertEqual(kernel.inspect_firewall(plan(), {}, True), (False, {"nat": [], "filter": []}))

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
            self.assertEqual(kernel.inspect_firewall(p, tables, False), (False, {"nat": [], "filter": []}))
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
        output = [rule for rule in hooks if rule[1] == "OUTPUT"]
        self.assertTrue(all("--path" in rule and "--ctdir" in rule for rule in output))
        regular = [rule for rule in output if "-s" in rule]
        self.assertTrue(all("--dport" not in rule for rule in regular))
        self.assertTrue(all(rule[rule.index("--ctdir") + 1] == "ORIGINAL" for rule in output))
        reply_guard = next(rule for rule in guards if "--ctdir" in rule and rule[rule.index("--ctdir") + 1] == "REPLY")
        self.assertEqual(reply_guard[-1], "RETURN")
        self.assertIn("--ctorigdst", guards[0])
        self.assertIn("!", guards[0])
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
        ipv4_guard, ipv6_guard, nat = transact.call_args_list
        self.assertEqual(ipv4_guard.args[0], "filter")
        self.assertTrue(ipv6_guard.kwargs["ipv6"])
        self.assertEqual(nat.args[0], "nat")

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
        self.assertTrue(all(line[:3] == ["-I", "FORWARD", "1"] for line in v6_filter if "FORWARD" in line[:2]))

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
        ipv6 = {"filter": {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(guards)}}
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
        v6 = {"filter": {"chains": {"OUTPUT": "ACCEPT"}, "rules": kernel.ipv6_guards(p)}}
        operation = request(p)
        operation["operation"] = "remove"
        with patch.object(kernel, "guest_lock"), patch.object(kernel, "grant"), patch.object(kernel, "guard") as guard, patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=[partial, v6, {}, {}]), patch.object(kernel, "transaction") as transact:
            conntrack.return_value.dump.return_value = []
            kernel.execute(operation)
        guard.assert_called_once_with(p, check_resolver=False, write_tools=True)
        ipv4, ipv6 = transact.call_args_list
        self.assertEqual({line[1] for line in ipv4.args[1] if line[0] == "-X"}, {"WPM2G_12345678", "WPM2F_12345678", "WPM2FB_12345678"})
        self.assertTrue(ipv6.kwargs["ipv6"])
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
            self.assertEqual(value, {"identity_matches": True, "rules_present": True, "rules_complete": True, "mappings_present": False, "unproven_mappings": 0})
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
            self.assertEqual(value, {"identity_matches": False, "rules_present": False, "rules_complete": False, "mappings_present": False, "unproven_mappings": 0})
            with self.subTest(reason=reason), self.assertRaises(kernel.Failure):
                self.observe(p, [snapshot(p), ipv6_snapshot(p)], identity_error=reason)
        # Any other drift is handled the same way: it can attest absence only.
        value = self.observe(plan(), [{}], identity_error="workload_outside_distro_cgroup")
        self.assertEqual(value, {"identity_matches": False, "rules_present": False, "rules_complete": False, "mappings_present": False, "unproven_mappings": 0})
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
    for table, rules in (("nat", nat), ("filter", filtered)):
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
            self.assertEqual(kernel.docker_networks(), {})
        ask.assert_not_called()
        with patch.object(kernel, "dockerd_running", return_value=True), patch.object(kernel.os.path, "exists", return_value=True), patch.object(kernel, "docker_request", return_value=DOCKER_NETWORKS), patch.object(kernel.os.path, "isdir", side_effect=lambda path: path.rsplit("/", 1)[-1] in PRESENT):
            self.assertEqual(kernel.docker_networks(), WANTED)
        with patch.object(kernel, "dockerd_running", return_value=True), patch.object(kernel.os.path, "exists", return_value=True), patch.object(kernel, "docker_request", side_effect=OSError("refused")):
            with self.assertRaisesRegex(kernel.Failure, "docker_networks_unavailable"):
                kernel.docker_networks()
        with patch.object(kernel, "dockerd_running", return_value=True), patch.object(kernel.os.path, "exists", return_value=False):
            with self.assertRaisesRegex(kernel.Failure, "docker_socket_missing"):
                kernel.docker_networks()

    def test_dockerd_is_found_by_process_name_in_the_targets_proc(self):
        with tempfile.TemporaryDirectory() as proc:
            for pid, name in (("1", "systemd"), ("42", "containerd"), ("self", "dockerd")):
                os.mkdir(os.path.join(proc, pid))
                with open(os.path.join(proc, pid, "comm"), "w") as handle:
                    handle.write(name + "\n")
            self.assertFalse(kernel.dockerd_running(proc))
            os.mkdir(os.path.join(proc, "77"))
            with open(os.path.join(proc, "77", "comm"), "w") as handle:
                handle.write("dockerd\n")
            self.assertTrue(kernel.dockerd_running(proc))

    def test_only_bridge_networks_with_an_interface_here_count(self):
        self.assertEqual(kernel.parse_docker_networks(DOCKER_NETWORKS, lambda name: name in PRESENT), WANTED)
        with self.assertRaises(kernel.Failure):
            kernel.parse_docker_networks({"not": "a list"}, lambda name: True)

    def test_network_rules_keep_subnets_local_redirect_the_rest_and_drop_leftovers(self):
        p = comprehensive_plan()
        nat, filtered = kernel.network_rules(p, {"docker0": WANTED["docker0"]})
        self.assertEqual([(rule[1], rule[rule.index("-i") + 1], rule[-1]) for rule in nat], [("WPM2B_12345678", "docker0", "RETURN"), ("WPM2B_12345678", "docker0", "WPM2_12345678")])
        self.assertEqual(nat[0][nat[0].index("-d") + 1], "172.17.0.0/16")
        self.assertEqual([rule[-1] for rule in filtered], ["RETURN"] * 4 + ["DROP"])
        self.assertEqual([rule[rule.index("-d") + 1] for rule in filtered[:-1]], ["172.17.0.0/16", *kernel.LOCAL_SCOPES["v4"]])
        self.assertTrue(all(rule[1] == "WPM2FB_12345678" for rule in filtered))
        # IPv6 block mode: no redirection, only the drop of what is not local.
        nat6, filtered6 = kernel.network_rules(p, WANTED, ipv6=True)
        self.assertEqual(nat6, [])
        self.assertEqual([rule[-1] for rule in filtered6].count("DROP"), 2)
        self.assertIn("fd00:db8:18::/64", [token for rule in filtered6 for token in rule])
        for rule in nat + filtered + filtered6:
            self.assertEqual(kernel.network_rule_owner(p, rule, rule in filtered6), rule[rule.index("-i") + 1])

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
        self.assertEqual([(table, ipv6, lines[0][0]) for table, ipv6, lines in calls], [("nat", False, "-D"), ("filter", False, "-D"), ("filter", True, "-D"), ("filter", False, "-I"), ("filter", True, "-I"), ("nat", False, "-I")])
        removed = [line for _, _, lines in calls for line in lines if line[0] == "-D"]
        self.assertTrue(all("docker0" in line for line in removed))
        for table, ipv6, lines in calls:
            if lines[0][0] != "-I":
                continue
            # Inserted at the top in reverse, so they end up in rule order.
            final = [["-A", line[1], *line[3:]] for line in reversed(lines)]
            expected = kernel.network_rules(p, new, ipv6)[0 if table == "nat" else 1]
            self.assertEqual(final, expected)
        # Nothing to do when the rules already match.
        result, calls = self.sync(p, tables, tables6, old)
        self.assertEqual((result["synced"]["added"], result["synced"]["removed"], calls), ([], [], []))

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
