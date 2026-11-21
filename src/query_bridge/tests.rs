// Query bridge protocol tests.
use super::*;
use std::io::Cursor;

#[test]
fn original_destination_bounds_remain_explicit_in_both_modes() {
    let mut plan: Plan = serde_json::from_value(serde_json::json!({
        "target": {
            "id": "{01234567-89ab-cdef-0123-456789abcdef}",
            "name": "WSLProxyLab-Target",
            "base_path": "D:\\WSL\\ProxyLab\\Target",
            "version": 2
        },
        "cgroup_ns": "cgroup:[4026534269]",
        "cgroup_root": "25:386884",
        "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
        "guest": "172.28.83.138",
        "ingress": "172.28.80.1:43771",
        "origins": ["172.28.80.1:43772"],
        "cookie": 305419896
    }))
    .unwrap();
    assert!(origin_allowed(&plan, "172.28.80.1:43772".parse().unwrap()));
    assert!(!origin_allowed(&plan, "93.184.216.34:443".parse().unwrap()));
    plan.system_dns = Some("10.255.255.254".parse().unwrap());
    assert!(!origin_allowed(&plan, "93.184.216.34:443".parse().unwrap()));
    plan.origins.clear();
    assert!(origin_allowed(&plan, "93.184.216.34:443".parse().unwrap()));
    plan.ipv6 = Some(crate::plan::Ipv6Plan {
        guest: "2001:db8:1::2".parse().unwrap(),
        ingress: "[fe80::1%2]:43771".parse().unwrap(),
    });
    assert!(origin_allowed(
        &plan,
        "[2001:db8:2::9]:443".parse().unwrap()
    ));
    assert!(!origin_allowed(&plan, "[fe80::1%2]:443".parse().unwrap()));
    for endpoint in [
        "127.0.0.1:443",
        "0.0.0.0:443",
        "169.254.1.1:443",
        "224.0.0.1:443",
        "93.184.216.34:0",
        "172.28.80.1:43771",
    ] {
        assert!(
            !origin_allowed(&plan, endpoint.parse().unwrap()),
            "{endpoint}"
        );
    }
}

#[test]
fn response_is_one_ordered_bounded_frame() {
    let mut reader = Cursor::new(b"{\"kind\":\"ready\"}\n{\"kind\":\"origins\",\"id\":7,\"origins\":[null,\"172.20.0.1:8080\"],\"kernel_read_us\":123,\"decode_lookup_us\":45}\n");
    let mut buffer = Vec::new();
    assert_eq!(
        read_response(&mut reader, &mut buffer).unwrap(),
        Response::Ready {}
    );
    assert_eq!(
        read_response(&mut reader, &mut buffer).unwrap(),
        Response::Origins {
            id: 7,
            origins: vec![None, Some("172.20.0.1:8080".parse().unwrap())],
            kernel_read_us: 123,
            decode_lookup_us: 45,
        }
    );
    assert!(
        read_response(&mut reader, &mut buffer)
            .unwrap_err()
            .contains("incomplete_response")
    );
}

#[test]
fn response_rejects_overflow_truncation_and_unknown_fields() {
    let mut buffer = Vec::new();
    let large = vec![b' '; RESPONSE_LIMIT + 20];
    let mut reader = Cursor::new(large);
    assert!(
        read_response(&mut reader, &mut buffer)
            .unwrap_err()
            .contains("response_limit")
    );
    assert_eq!(reader.position(), (RESPONSE_LIMIT + 1) as u64);
    for frame in [
        "{\"kind\":\"ready\"}",
        "{\"kind\":\"ready\",\"operation\":\"install\"}\n",
        "{\"kind\":\"origin\",\"id\":1}\n",
        "{\"kind\":\"origins\",\"id\":1}\n",
        "{\"kind\":\"fatal\",\"error\":\"bad\\nerror\"}\n",
    ] {
        assert!(
            read_response(&mut Cursor::new(frame), &mut buffer).is_err(),
            "{frame}"
        );
    }
}

#[test]
fn response_rejects_malformed_or_unbounded_guest_timings() {
    let mut buffer = Vec::new();
    for metadata in [
        "",
        ",\"kernel_read_us\":1",
        ",\"kernel_read_us\":-1,\"decode_lookup_us\":0",
        ",\"kernel_read_us\":1.5,\"decode_lookup_us\":0",
        ",\"kernel_read_us\":\"1\",\"decode_lookup_us\":0",
        ",\"kernel_read_us\":null,\"decode_lookup_us\":0",
        ",\"kernel_read_us\":0,\"decode_lookup_us\":12000001",
        ",\"kernel_read_us\":12000000,\"decode_lookup_us\":1",
        ",\"kernel_read_us\":18446744073709551615,\"decode_lookup_us\":1",
        ",\"kernel_read_us\":18446744073709551616,\"decode_lookup_us\":0",
        ",\"kernel_read_us\":0,\"decode_lookup_us\":0,\"kernel_read_us\":1",
        ",\"kernel_read_us\":0,\"decode_lookup_us\":0,\"other_us\":1",
    ] {
        let frame = format!("{{\"kind\":\"origins\",\"id\":1,\"origins\":[null]{metadata}}}\n");
        assert!(
            read_response(&mut Cursor::new(frame), &mut buffer).is_err(),
            "{metadata}"
        );
    }
    for (kernel_read_us, decode_lookup_us) in [(0, 0), (12_000_000, 0), (0, 12_000_000)] {
        let frame = format!(
            "{{\"kind\":\"origins\",\"id\":1,\"origins\":[null],\"kernel_read_us\":{kernel_read_us},\"decode_lookup_us\":{decode_lookup_us}}}\n"
        );
        assert!(read_response(&mut Cursor::new(frame), &mut buffer).is_ok());
    }
}

#[test]
fn lookup_failure_remains_distinct_from_transport_failure() {
    let mut buffer = Vec::new();
    let frame = b"{\"kind\":\"lookup_error\",\"id\":9,\"error\":\"mapping_missing_ambiguous_or_unowned\"}\n";
    assert_eq!(
        read_response(&mut Cursor::new(frame), &mut buffer).unwrap(),
        Response::LookupError {
            id: 9,
            error: "mapping_missing_ambiguous_or_unowned".into()
        }
    );
}

#[test]
fn requests_have_only_fixed_readonly_fields_and_fit_the_bound() {
    for protocol in ["tcp", "udp"] {
        let bytes = serde_json::to_vec(&Query {
            id: u64::MAX,
            lookups: vec![
                Lookup {
                    protocol,
                    peer: "255.255.255.255:65535".parse().unwrap()
                };
                MAX_LOOKUPS
            ],
        })
        .unwrap();
        assert!(bytes.len() < REQUEST_LIMIT);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 2);
        assert!(value.get("operation").is_none());
        assert_eq!(value["lookups"][0]["protocol"], protocol);
    }
}

#[test]
fn requests_preserve_ipv6_scope_in_the_wire_endpoint() {
    let query = Query {
        id: 1,
        lookups: vec![Lookup {
            protocol: "tcp",
            peer: "[2001:db8:1::2]:45000".parse().unwrap(),
        }],
    };
    let value: serde_json::Value = serde_json::to_value(query).unwrap();
    assert_eq!(value["lookups"][0]["peer"], "[2001:db8:1::2]:45000");
}
