"""Pure guest-kernel boundary tests; no guest or network operation is performed."""

import copy
import json
import os
import struct
import tempfile
import unittest
from unittest.mock import patch

import kernel


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
    return result


def snapshot(p=None):
    p = p or plan()
    chain, _, hooks, body, guards = kernel.artifacts(p)
    tables = {
        "nat": {"chains": {"OUTPUT": "ACCEPT", chain: "-"}, "rules": copy.deepcopy(hooks + body)},
        "filter": {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(guards)},
    }
    if p.get("system_dns") is not None:
        tables["filter"]["chains"]["WPM2G_" + f"{p['cookie']:08x}"] = "-"
    return tables


def ipv6_snapshot(p):
    return {"filter": {"chains": {"OUTPUT": "ACCEPT"}, "rules": copy.deepcopy(kernel.ipv6_guards(p))}}


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
    def test_nested_tuple_round_trip_and_opaque_id_bytes(self):
        value = entry(identifier=0x78563412)
        parsed = kernel.parse_entry(encoded_entry(value))
        self.assertEqual(parsed, value)
        self.assertEqual(struct.pack("!I", parsed["id"]), b"\x78\x56\x34\x12")
        with self.assertRaises(kernel.Failure):
            kernel.parse_entry(encoded_entry(value, include_id=False))

    def test_malformed_and_duplicate_attributes_fail_closed(self):
        for data in (b"\0", b"\x03\0\x01\0", b"\x08\0\x01\0", kernel.attribute(1, b"one") + kernel.attribute(1, b"two")):
            with self.subTest(data=data), self.assertRaises(kernel.Failure):
                kernel.attributes(data)

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


class FirewallTests(unittest.TestCase):
    def test_restore_preserves_xtables_negation_token(self):
        with patch.object(kernel, "run") as run:
            kernel.transaction("filter", [["-I", "OUTPUT", "!", "-d", "127.0.0.0/8", "-j", "DROP"]], test=True)
        self.assertEqual(run.call_args.args[1], "*filter\n-I OUTPUT ! -d 127.0.0.0/8 -j DROP\nCOMMIT\n")

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
        established = [rule for rule in guards if "ESTABLISHED,RELATED" in rule]
        self.assertTrue(all("-p" in rule and rule[rule.index("-p") + 1] in ("tcp", "udp") for rule in established))
        self.assertTrue(all("--ctorigsrc" in rule or ("--ctorigdst" in rule and "--ctorigdstport" in rule) for rule in established))
        snat = [rule for rule in hooks if "SNAT" in rule]
        self.assertEqual(len(snat), 2)
        for rule in snat:
            self.assertEqual(rule[rule.index("--ctorigdst") + 1], p["system_dns"])
            self.assertEqual(rule[rule.index("--ctorigdstport") + 1], "53")
            self.assertEqual(rule[rule.index("--to-source") + 1], p["guest"])
            self.assertIn("connmark", rule)
        with patch.object(kernel, "transaction") as transact:
            kernel.install_rules(p, test=True)
        ipv4_guard, ipv6_guard, nat = transact.call_args_list
        self.assertEqual(ipv4_guard.args[0], "filter")
        self.assertTrue(ipv6_guard.kwargs["ipv6"])
        self.assertEqual(nat.args[0], "nat")

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
        self.assertTrue(all("::1/128" in rule and "cgroup" in rule for rule in guards))
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
        self.assertEqual(ipv4.args[1][-1], ["-X", "WPM2G_12345678"])
        self.assertTrue(ipv6.kwargs["ipv6"])
        self.assertTrue(all(rule[0] in ("-D", "-X") for call in transact.call_args_list for rule in call.args[1]))


class InspectionTests(unittest.TestCase):
    def observe(self, p, tables, entries=None, ipv6_entries=None, identity_error=None, pending=False):
        operation = request(p)
        operation["operation"] = "inspect"
        failure = kernel.Failure(identity_error) if identity_error else None
        with patch.object(kernel, "guest_lock") as lock, patch.object(kernel, "guard", side_effect=failure) as guard, patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=tables), patch.object(kernel, "transaction") as transact, patch.object(kernel, "install_rules") as install, patch.object(kernel, "grant") as grant, patch.object(kernel, "grant_pending", return_value=pending):
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
            self.assertEqual(value, {"identity_matches": True, "rules_present": True, "rules_complete": True, "mappings_present": False})
            partial = snapshot(p)
            del partial["nat"]
            tables = [partial] + ([ipv6_snapshot(p)] if p.get("system_dns") is not None else [])
            value = self.observe(p, tables)
            self.assertTrue(value["rules_present"])
            self.assertFalse(value["rules_complete"])

    def test_absence_and_live_connmark_are_independently_observed(self):
        for p, values in ((plan(), [entry()]), (comprehensive_plan(), [comprehensive_entry()])):
            tables = [{}] + ([{}] if p.get("system_dns") is not None else [])
            value = self.observe(p, tables, entries=values)
            self.assertFalse(value["rules_present"])
            self.assertTrue(value["mappings_present"])
            absent = self.observe(p, tables)
            self.assertFalse(absent["rules_present"] or absent["mappings_present"] or absent["rules_complete"])

    def test_changed_identity_can_only_attest_independently_proved_absence(self):
        for reason in ("boot_changed", "cgroup_namespace_changed", "cgroup_root_changed", "guest_address_changed"):
            p = comprehensive_plan()
            other = copy.deepcopy(p)
            other["cookie"] += 1
            foreign = snapshot(other)
            foreign["filter"]["rules"][0].extend(["--unrelated-shape", "unreachable"])
            value = self.observe(p, [foreign, ipv6_snapshot(other)], identity_error=reason)
            self.assertEqual(value, {"identity_matches": False, "rules_present": False, "rules_complete": False, "mappings_present": False})
            with self.subTest(reason=reason), self.assertRaises(kernel.Failure):
                self.observe(p, [snapshot(p), ipv6_snapshot(p)], identity_error=reason)
        with self.assertRaises(kernel.Failure):
            self.observe(plan(), [{}], identity_error="workload_outside_distro_cgroup")

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
        cases = [
            (corrupt_v6, [], []),
            (ipv6_snapshot(p), [corrupt_mapping], []),
            (ipv6_snapshot(p), [], [{"mark": p["cookie"]}]),
        ]
        operation = request(p)
        operation["operation"] = "remove"
        for v6, mappings, v6_mappings in cases:
            with self.subTest(v6=v6, mappings=mappings), patch.object(kernel, "guest_lock"), patch.object(kernel, "guard"), patch.object(kernel, "grant") as grant, patch.object(kernel, "Conntrack") as conntrack, patch.object(kernel, "firewall", side_effect=[snapshot(p), v6]), patch.object(kernel, "transaction") as transact:
                conntrack.return_value.dump.side_effect = lambda ipv6=False: v6_mappings if ipv6 else mappings
                with self.assertRaises(kernel.Failure):
                    kernel.execute(operation)
                grant.assert_called_once_with(p, "revoke")
                transact.assert_not_called()
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
        with self.assertRaises(kernel.Failure):
            self.observe(comprehensive_plan(), [{}, {}], ipv6_entries=[{"mark": plan()["cookie"]}])


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
