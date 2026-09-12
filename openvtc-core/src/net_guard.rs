//! Which hosts an outbound probe must never be pointed at.
//!
//! **Keep in sync with `affinidi-did-web`** (`src/lib.rs`, `host_is_blocked` /
//! `ip_is_blocked`; copied from 0.1.4). That crate already guards DID
//! *resolution* and exports the connect-time half of the check
//! ([`affinidi_did_web::guarded_dns_resolver`]), but keeps this classifier
//! private. Replace this module with the exported API once one is published, so
//! resolution and probing enforce one policy rather than two copies of it.
//!
//! This classifies a host **as written in the URL**. A hostname that resolves
//! to one of these addresses is refused separately, at connect time, by the DNS
//! resolver the probe client installs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `host` is one an outbound request must refuse: loopback, RFC-1918 /
/// unique-local, carrier-grade NAT, link-local (which includes the
/// cloud-metadata address `169.254.169.254`), unspecified, or broadcast. Bare
/// `localhost` and `*.localhost` / `*.local` are refused by name.
///
/// Takes the host as `reqwest::Url::host_str` returns it: already WHATWG
/// canonicalised (so `2130706433` and `0x7f.1` arrive as `127.0.0.1`), with
/// IPv6 literals in brackets.
pub(crate) fn is_blocked_host(host: &str) -> bool {
    // A trailing root dot is part of a legal hostname and survives URL
    // normalisation, so `localhost.` must normalise to `localhost` before the
    // name comparisons -- otherwise it walks straight through this guard.
    let h = host
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(a) => is_blocked_ip(a),
        Err(_) => false,
    }
}

/// Whether an address must never be connected to.
fn is_blocked_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => ipv4_is_blocked(a),
        IpAddr::V6(a) => ipv6_is_blocked(a),
    }
}

fn ipv4_is_blocked(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()
        || a.is_private()
        || a.is_link_local() // 169.254.0.0/16 — covers cloud metadata 169.254.169.254
        || a.is_broadcast()
        || o[0] == 0 // 0.0.0.0/8 "this network" — includes the unspecified address
        // 100.64.0.0/10 carrier-grade NAT: the Alibaba/Oracle metadata address
        // 100.100.100.200 lives here, as do the node/pod CIDRs of many
        // Kubernetes deployments. `Ipv4Addr::is_shared` is still unstable.
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
}

fn ipv6_is_blocked(a: Ipv6Addr) -> bool {
    if a.is_loopback() || a.is_unspecified() {
        return true;
    }
    // Both IPv4-mapped (::ffff:a.b.c.d) and the deprecated IPv4-compatible
    // (::a.b.c.d) forms reach the same v4 target on stacks that still route
    // them, and `to_ipv4` — unlike `to_ipv4_mapped` — covers both.
    if let Some(v4) = a.to_ipv4() {
        return ipv4_is_blocked(v4);
    }
    let s = a.segments();
    // NAT64 well-known prefix 64:ff9b::/96 embeds a v4 destination in the low
    // 32 bits, so classify that destination.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        let v4 = Ipv4Addr::from((u32::from(s[6]) << 16) | u32::from(s[7]));
        return ipv4_is_blocked(v4);
    }
    (s[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (s[0] & 0xffc0) == 0xfec0 // deprecated site-local fec0::/10
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors copied from `affinidi-did-web` 0.1.4 — keep in sync with it.

    #[test]
    fn host_guard_blocks_internal_and_metadata() {
        for h in [
            "127.0.0.1",
            "0.0.0.0",
            "0.1.2.3", // 0.0.0.0/8 "this network"
            "10.0.0.5",
            "172.16.9.9",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.100.100.200", // Alibaba/Oracle metadata, in CGNAT space
            "100.64.0.1",      // CGNAT lower bound
            "100.127.255.254", // CGNAT upper bound
            "192.0.0.1",       // IETF protocol assignments
            "198.19.0.1",      // benchmarking range
            "255.255.255.255", // broadcast
            "localhost",
            "localhost.", // trailing root dot
            "LOCALHOST",
            "svc.localhost",
            "svc.localhost.",
            "printer.local",
            "printer.local.",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
            "::ffff:169.254.169.254",
            "::127.0.0.1",     // IPv4-compatible loopback
            "64:ff9b::7f00:1", // NAT64-embedded loopback
            "fc00::1",         // unique-local
            "fe80::1",         // link-local
            "fec0::1",         // deprecated site-local
        ] {
            assert!(is_blocked_host(h), "{h} should be blocked");
        }
    }

    #[test]
    fn host_guard_allows_public_hosts() {
        for h in [
            "example.com",
            "example.com.",
            "did.example.org",
            "localhost.example.com", // "localhost" only as the whole name or a suffix label
            "8.8.8.8",
            "99.64.0.1",   // just below CGNAT
            "100.63.0.1",  // just below CGNAT
            "100.128.0.1", // just above CGNAT
            "2606:4700:4700::1111",
            "64:ff9b::808:808", // NAT64-embedded public address
        ] {
            assert!(!is_blocked_host(h), "{h} should be allowed");
        }
    }
}
