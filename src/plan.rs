use crate::{host, kernel, probe::Snapshot};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::num::NonZeroU16;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub target: host::Distro,
    pub cgroup_ns: String,
    pub cgroup_root: String,
    pub boot_id: String,
    pub guest: Ipv4Addr,
    pub ingress: SocketAddrV4,
    pub origins: Vec<SocketAddrV4>,
    pub cookie: u32,
    // Omitted for old M1 journals: their kernel rule tag is a digest of the plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_dns: Option<Ipv4Addr>,
    /// Optional IPv6 ingress identity. Older journals and NAT-only targets
    /// leave this absent until the transparent IPv6 path is verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Ipv6Plan>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ipv6Plan {
    pub guest: Ipv6Addr,
    pub ingress: SocketAddrV6,
}

fn scope(
    guest: Ipv4Addr,
    ingress: SocketAddrV4,
    origins: &[SocketAddrV4],
    system_dns: Option<Ipv4Addr>,
) -> Result<(), String> {
    let local = |ip: Ipv4Addr| {
        !ip.is_unspecified()
            && !ip.is_loopback()
            && !ip.is_multicast()
            && !ip.is_broadcast()
            && !ip.is_link_local()
    };
    if !local(guest)
        || !local(*ingress.ip())
        || ingress.ip() == &guest
        || ingress.port() < 1024
        || (system_dns.is_none() && origins.is_empty())
        || system_dns.is_some_and(|ip| {
            !origins.is_empty() || !crate::managed::valid_resolver(ip) || ip == guest
        })
        || origins.len() > 8
    {
        return Err("invalid_lab_scope".into());
    }
    for (i, ep) in origins.iter().enumerate() {
        if (ep.ip() != ingress.ip() && *ep.ip() != guest)
            || ep.port() < 1024
            || ep.port() == ingress.port()
            || origins[..i].contains(ep)
        {
            return Err(format!("invalid_or_duplicate_lab_origin:{ep}"));
        }
    }
    Ok(())
}

impl Plan {
    pub(crate) fn validate(&self) -> Result<(), String> {
        scope(self.guest, self.ingress, &self.origins, self.system_dns)?;
        if let Some(ipv6) = &self.ipv6 {
            if ipv6.guest.is_unspecified()
                || ipv6.guest.is_loopback()
                || ipv6.guest.is_multicast()
                || ipv6.guest.is_unicast_link_local()
                || ipv6.ingress.ip().is_unspecified()
                || ipv6.ingress.ip().is_multicast()
                || ipv6.ingress.port() < 1024
                || ipv6.guest == *ipv6.ingress.ip()
            {
                return Err("invalid_ipv6_scope".into());
            }
        }
        kernel::validate(self)
    }

    pub fn new(
        target: &host::Distro,
        s: &Snapshot,
        port: NonZeroU16,
        origins: Vec<SocketAddrV4>,
        system_dns: Option<Ipv4Addr>,
    ) -> Result<Self, String> {
        if !s.identity_valid
            || !s.blockers.is_empty()
            || s.cgroup_path != "/"
            || s.cgroup_mount_root != "/"
        {
            return Err("target_scope_unverified".into());
        }
        let value = |key: &str| {
            s.evidence
                .get(key)
                .filter(|e| e.status == "ok")
                .map(|e| e.value.as_str())
                .ok_or_else(|| format!("missing_evidence:{key}"))
        };
        let gw = s.gateway.ok_or("gateway_missing")?;
        let route = value("network.gateway_route")?;
        let words: Vec<_> = route.split_whitespace().collect();
        let mut sources = words.windows(2).filter(|w| w[0] == "src");
        let guest = sources.next().ok_or("guest_source_missing")?[1]
            .parse::<Ipv4Addr>()
            .map_err(|_| "guest_source_invalid")?;
        if sources.next().is_some() {
            return Err("ambiguous_guest_source".into());
        }
        let ingress = SocketAddrV4::new(gw, port.get());
        scope(guest, ingress, &origins, system_dns)?;
        // RandomState uses OS-seeded keys. The mark is an ownership discriminator, not a secret;
        // the kernel precheck must also exclude collisions before any rule is committed.
        use std::hash::{BuildHasher, RandomState};
        let cookie = RandomState::new().hash_one(&target.id) as u32;
        if cookie == 0 {
            return Err("zero_instance_mark_retry_start".into());
        }
        // Scoped mode has an explicit IPv4 destination list and no IPv6
        // destination list. Keep the optional IPv6 transparent path coupled
        // to managed mode until both families share the same policy runtime.
        let ipv6 = system_dns.is_some().then(|| ipv6_scope(s, port)).flatten();
        Ok(Self {
            target: target.clone(),
            cgroup_ns: s.cgroup_ns.clone(),
            cgroup_root: s.cgroup_root.clone(),
            boot_id: value("identity.boot_id")?.into(),
            guest,
            ingress,
            origins,
            cookie,
            system_dns,
            ipv6,
        })
    }
}

fn ipv6_scope(snapshot: &Snapshot, port: NonZeroU16) -> Option<Ipv6Plan> {
    let evidence = &snapshot.evidence;
    let addresses = evidence
        .get("baseline.addresses_v6")
        .filter(|item| item.status == "ok")
        .map(|item| item.value.as_str())?;
    let guest = addresses.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        let address = fields
            .windows(2)
            .find(|pair| pair[0] == "inet6" && pair[1].contains('/'))?
            .get(1)?
            .split_once('/')?
            .0
            .parse::<Ipv6Addr>()
            .ok()?;
        fields
            .windows(2)
            .any(|pair| pair == ["scope", "global"])
            .then_some(address)
    })?;
    let routes = evidence
        .get("baseline.routes_v6")
        .filter(|item| item.status == "ok")
        .map(|item| item.value.as_str())?;
    let gateway = routes.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.first() == Some(&"default"))
            .then(|| {
                fields
                    .windows(2)
                    .find(|pair| pair[0] == "via")?
                    .get(1)?
                    .parse()
                    .ok()
            })
            .flatten()
    })?;
    let links = evidence
        .get("baseline.links")
        .filter(|item| item.status == "ok")
        .map(|item| item.value.as_str())?;
    let scope_id = links.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        let index = fields.first()?.strip_suffix(':')?.parse::<u32>().ok()?;
        let name = fields.get(1)?.strip_suffix(':')?;
        (name == "eth0").then_some(index)
    })?;
    Some(Ipv6Plan {
        guest,
        ingress: SocketAddrV6::new(gateway, port.get(), 0, scope_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_loop_and_outside_destinations() {
        let guest = Ipv4Addr::new(172, 28, 4, 5);
        let listener = "172.28.0.1:41000".parse().unwrap();
        for ep in [
            "172.28.0.1:41000",
            "172.28.4.5:53",
            "8.8.8.8:41001",
            "127.0.0.1:41001",
        ] {
            assert!(scope(guest, listener, &[ep.parse().unwrap()], None).is_err());
        }
        assert!(
            scope(
                guest,
                listener,
                &["172.28.4.5:41001".parse().unwrap()],
                None
            )
            .is_ok()
        );
        let dns = Some(Ipv4Addr::new(10, 255, 255, 254));
        assert!(scope(guest, listener, &[], dns).is_ok());
        assert!(scope(guest, listener, &["172.28.4.5:41001".parse().unwrap()], dns).is_err());
    }

    #[test]
    fn derives_ipv6_guest_and_scoped_gateway_when_a_default_route_exists() {
        let mut evidence = std::collections::BTreeMap::new();
        for (key, value) in [
            (
                "baseline.addresses_v6",
                "1: lo    inet6 ::1/128 scope host\n2: eth0    inet6 2001:db8:1::2/64 scope global",
            ),
            (
                "baseline.routes_v6",
                "default via fe80::1 dev eth0 proto ra",
            ),
            (
                "baseline.links",
                "1: lo: <LOOPBACK>\n2: eth0: <BROADCAST,UP>",
            ),
        ] {
            evidence.insert(
                key.to_owned(),
                crate::probe::Observation {
                    status: "ok".into(),
                    value: value.into(),
                },
            );
        }
        let snapshot = Snapshot {
            registered_name: "fixture".into(),
            guest_name: "fixture".into(),
            cgroup_ns: String::new(),
            cgroup_root: String::new(),
            cgroup_path: String::new(),
            cgroup_mount_root: String::new(),
            identity_valid: true,
            pid1: String::new(),
            uid: Some(0),
            cap_net_admin: true,
            networking_mode: "nat".into(),
            gateway: None,
            blockers: Vec::new(),
            baseline_fingerprints: Default::default(),
            evidence,
        };
        let ipv6 = ipv6_scope(&snapshot, NonZeroU16::new(43531).unwrap()).unwrap();
        assert_eq!(ipv6.guest, "2001:db8:1::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ipv6.ingress.ip(), &"fe80::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ipv6.ingress.scope_id(), 2);
    }
}
