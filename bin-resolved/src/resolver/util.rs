use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use dns_types::protocol::types::*;

/// The result of a name resolution attempt.
///
/// If this is a `CNAME`, it should be added to the answer section of
/// the response message, and resolution repeated for the CNAME.  This
/// may build up a chain of `CNAME`s for some names.
///
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum ResolvedRecord {
    Authoritative {
        rrs: Vec<ResourceRecord>,
        authority_rrs: Vec<ResourceRecord>,
    },
    AuthoritativeNameError {
        authority_rrs: Vec<ResourceRecord>,
    },
    NonAuthoritative {
        rrs: Vec<ResourceRecord>,
    },
}

impl ResolvedRecord {
    pub fn rrs(self) -> Vec<ResourceRecord> {
        match self {
            ResolvedRecord::Authoritative { rrs, .. } => rrs,
            ResolvedRecord::AuthoritativeNameError { .. } => Vec::new(),
            ResolvedRecord::NonAuthoritative { rrs } => rrs,
        }
    }
}

/// Given a set of RRs and a domain name we're looking for, follow
/// `CNAME`s in the response and return the final name (which is the
/// name that will have the non-`CNAME` records associated with it).
///
/// Returns `None` if CNAMEs form a loop, or there is no RR which
/// matches the target name (a CNAME or one with the right type).
pub fn follow_cnames(
    rrs: &[ResourceRecord],
    target: &DomainName,
    qtype: &QueryType,
) -> Option<(DomainName, HashMap<DomainName, DomainName>)> {
    let mut got_match = false;
    let mut cname_map = HashMap::<DomainName, DomainName>::new();
    for rr in rrs {
        if &rr.name == target && rr.rtype_with_data.matches(qtype) {
            got_match = true;
        }
        if let RecordTypeWithData::CNAME { cname } = &rr.rtype_with_data {
            cname_map.insert(rr.name.clone(), cname.clone());
        }
    }

    let mut seen = HashSet::new();
    let mut final_name = target.clone();
    while let Some(target) = cname_map.get(&final_name) {
        if seen.contains(target) {
            return None;
        }
        seen.insert(target.clone());
        final_name = target.clone();
    }

    if got_match || !seen.is_empty() {
        Some((final_name, cname_map))
    } else {
        None
    }
}

/// Given a set of RRs and a domain name we're looking for, look for
/// better matching NS RRs (by comparing the current match count).
/// Returns the new matching superdomain and the nameserver hostnames.
pub fn get_better_ns_names(
    rrs: &[ResourceRecord],
    target: &DomainName,
    current_match_count: usize,
) -> Option<(DomainName, HashSet<DomainName>)> {
    let mut ns_names = HashSet::new();
    let mut match_count = current_match_count;
    let mut match_name = None;

    for rr in rrs {
        if let RecordTypeWithData::NS { nsdname } = &rr.rtype_with_data {
            if target.is_subdomain_of(&rr.name) {
                match rr.name.labels.len().cmp(&match_count) {
                    Ordering::Greater => {
                        match_count = rr.name.labels.len();
                        match_name = Some(rr.name.clone());

                        ns_names.clear();
                        ns_names.insert(nsdname.clone());
                    }
                    Ordering::Equal => {
                        ns_names.insert(nsdname.clone());
                    }
                    Ordering::Less => (),
                }
            }
        }
    }

    match_name.map(|mn| (mn, ns_names))
}

/// Given a set of RRs and a domain name we're looking for, follow any
/// `CNAME`s in the response and get the address from the final `A`
/// record.
pub fn get_ip(rrs: &[ResourceRecord], target: &DomainName) -> Option<Ipv4Addr> {
    if let Some((final_name, _)) = follow_cnames(rrs, target, &QueryType::Record(RecordType::A)) {
        for rr in rrs {
            match &rr.rtype_with_data {
                RecordTypeWithData::A { address } if rr.name == final_name => {
                    return Some(*address);
                }
                _ => (),
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use dns_types::protocol::types::test_util::*;

    use super::*;

    #[test]
    fn follow_cnames_empty() {
        assert_eq!(
            None,
            follow_cnames(&[], &domain("www.example.com."), &QueryType::Wildcard)
        );
    }

    #[test]
    fn follow_cnames_no_name_match() {
        assert_eq!(
            None,
            follow_cnames(
                &[a_record("www.example.net.", Ipv4Addr::new(1, 1, 1, 1))],
                &domain("www.example.com."),
                &QueryType::Wildcard
            )
        );
    }

    #[test]
    fn follow_cnames_no_type_match() {
        assert_eq!(
            None,
            follow_cnames(
                &[a_record("www.example.net.", Ipv4Addr::new(1, 1, 1, 1))],
                &domain("www.example.com."),
                &QueryType::Record(RecordType::NS)
            )
        );
    }

    #[test]
    fn follow_cnames_no_cname() {
        let rr_a = a_record("www.example.com.", Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            Some((domain("www.example.com."), HashMap::new())),
            follow_cnames(&[rr_a], &domain("www.example.com."), &QueryType::Wildcard)
        );
    }

    #[test]
    fn follow_cnames_chain() {
        let rr_cname1 = cname_record("www.example.com.", "www2.example.com.");
        let rr_cname2 = cname_record("www2.example.com.", "www3.example.com.");
        let rr_a = a_record("www3.example.com.", Ipv4Addr::new(127, 0, 0, 1));

        let mut expected_map = HashMap::new();
        expected_map.insert(domain("www.example.com."), domain("www2.example.com."));
        expected_map.insert(domain("www2.example.com."), domain("www3.example.com."));

        // order of records does not matter, so pick the "worst"
        // order: the records are in the opposite order to what we'd
        // expect
        assert_eq!(
            Some((domain("www3.example.com."), expected_map)),
            follow_cnames(
                &[rr_a, rr_cname2, rr_cname1],
                &domain("www.example.com."),
                &QueryType::Wildcard
            )
        );
    }

    #[test]
    fn follow_cnames_loop() {
        let rr_cname1 = cname_record("www.example.com.", "bad.example.com.");
        let rr_cname2 = cname_record("bad.example.com.", "www.example.com.");

        assert_eq!(
            None,
            follow_cnames(
                &[rr_cname1, rr_cname2],
                &domain("www.example.com."),
                &QueryType::Wildcard
            )
        )
    }

    #[test]
    fn get_better_ns_names_no_match() {
        let rr_ns = ns_record("example.", "ns1.icann.org.");
        assert_eq!(
            None,
            get_better_ns_names(&[rr_ns], &domain("www.example.com."), 0)
        );
    }

    #[test]
    fn get_better_ns_names_no_better() {
        let rr_ns = ns_record("com.", "ns1.icann.org.");
        assert_eq!(
            None,
            get_better_ns_names(&[rr_ns], &domain("www.example.com."), 2)
        );
    }

    #[test]
    fn get_better_ns_names_better() {
        let rr_ns = ns_record("example.com.", "ns2.icann.org.");
        assert_eq!(
            Some((
                domain("example.com."),
                [domain("ns2.icann.org.")].into_iter().collect()
            )),
            get_better_ns_names(&[rr_ns], &domain("www.example.com."), 0)
        );
    }

    #[test]
    fn get_better_ns_names_better_better() {
        let rr_ns1 = ns_record("example.com.", "ns2.icann.org.");
        let rr_ns2 = ns_record("www.example.com.", "ns3.icann.org.");
        assert_eq!(
            Some((
                domain("www.example.com."),
                [domain("ns3.icann.org.")].into_iter().collect()
            )),
            get_better_ns_names(&[rr_ns1, rr_ns2], &domain("www.example.com."), 0)
        );
    }

    #[test]
    fn get_ip_no_match() {
        let a_rr = a_record("www.example.net.", Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(None, get_ip(&[a_rr], &domain("www.example.com.")));
    }

    #[test]
    fn get_ip_direct_match() {
        let a_rr = a_record("www.example.com.", Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            Some(Ipv4Addr::new(127, 0, 0, 1)),
            get_ip(&[a_rr], &domain("www.example.com."))
        );
    }

    #[test]
    fn get_ip_cname_match() {
        let cname_rr = cname_record("www.example.com.", "www.example.net.");
        let a_rr = a_record("www.example.net.", Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            Some(Ipv4Addr::new(127, 0, 0, 1)),
            get_ip(&[cname_rr, a_rr], &domain("www.example.com."))
        );
    }
}

#[cfg(test)]
pub mod test_util {
    use dns_types::protocol::types::test_util::*;
    use dns_types::zones::types::*;
    use std::net::Ipv4Addr;

    use super::*;

    pub fn zones() -> Zones {
        let mut zone_na = Zone::default();
        zone_na.insert(
            &domain("blocked.example.com."),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(0, 0, 0, 0),
            },
            300,
        );
        zone_na.insert(
            &domain("cname-and-a.example.com."),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(1, 1, 1, 1),
            },
            300,
        );
        zone_na.insert(
            &domain("cname-and-a.example.com."),
            RecordTypeWithData::CNAME {
                cname: domain("cname-target.example.com."),
            },
            300,
        );
        zone_na.insert(
            &domain("a.example.com."),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(1, 1, 1, 1),
            },
            300,
        );
        zone_na.insert(
            &domain("delegated.example.com."),
            RecordTypeWithData::NS {
                nsdname: domain("ns.delegated.example.com."),
            },
            300,
        );

        let mut zone_a = Zone::new(
            domain("authoritative.example.com."),
            Some(SOA {
                mname: domain("mname."),
                rname: domain("rname."),
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0,
            }),
        );
        zone_a.insert(
            &domain("authoritative.example.com."),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(1, 1, 1, 1),
            },
            300,
        );
        zone_a.insert(
            &domain("cname-a.authoritative.example.com."),
            RecordTypeWithData::CNAME {
                cname: domain("authoritative.example.com."),
            },
            300,
        );
        zone_a.insert(
            &domain("cname-na.authoritative.example.com."),
            RecordTypeWithData::CNAME {
                cname: domain("a.example.com."),
            },
            300,
        );
        zone_a.insert(
            &domain("delegated.authoritative.example.com."),
            RecordTypeWithData::NS {
                nsdname: domain("ns.delegated.authoritative.example.com."),
            },
            300,
        );

        let mut zones = Zones::new();
        zones.insert(zone_na);
        zones.insert(zone_a);

        zones
    }

    pub fn zones_soa_rr() -> ResourceRecord {
        zones()
            .get(&domain("authoritative.example.com."))
            .unwrap()
            .soa_rr()
            .unwrap()
    }
}
