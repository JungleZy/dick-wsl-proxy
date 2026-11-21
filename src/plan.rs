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
                || ipv6.ingress.ip().is_unicast_link_local()
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
            ipv6: None,
        })
    }
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
}
