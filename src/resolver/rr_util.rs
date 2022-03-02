use std::collections::{HashMap, HashSet};

use crate::protocol::wire_types::*;

/// Given a set of RRs and a domain name we're looking for, follow
/// `CNAME`s in the response and return the final name (which is the
/// name that will have the non-`CNAME` records associated with it).
///
/// Returns `None` if CNAMEs form a loop, or there is no RR which
/// matches the target name (a CNAME or one with the right type &
/// class).
pub fn follow_cnames(
    rrs: &[ResourceRecord],
    target: &DomainName,
    qclass: &QueryClass,
    qtype: &QueryType,
) -> Option<(DomainName, HashMap<DomainName, DomainName>)> {
    let mut got_match = false;
    let mut cname_map = HashMap::<DomainName, DomainName>::new();
    for rr in rrs {
        if &rr.name == target && rr.rclass.matches(qclass) && rr.rtype_with_data.matches(qtype) {
            got_match = true;
        }
        if let RecordTypeWithData::Named {
            rtype: RecordType::CNAME,
            name,
        } = &rr.rtype_with_data
        {
            cname_map.insert(rr.name.clone(), name.clone());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follow_cnames_empty() {
        assert_eq!(
            None,
            follow_cnames(
                &[],
                &domain("www.example.com"),
                &QueryClass::Wildcard,
                &QueryType::Wildcard
            )
        );
    }

    #[test]
    fn follow_cnames_no_name_match() {
        assert_eq!(
            None,
            follow_cnames(
                &[a_record("www.example.net", vec![1, 1, 1, 1])],
                &domain("www.example.com"),
                &QueryClass::Wildcard,
                &QueryType::Wildcard
            )
        );
    }

    #[test]
    fn follow_cnames_no_class_match() {
        assert_eq!(
            None,
            follow_cnames(
                &[a_record("www.example.net", vec![1, 1, 1, 1])],
                &domain("www.example.com"),
                &QueryClass::Record(RecordClass::CH),
                &QueryType::Wildcard
            )
        );
    }

    #[test]
    fn follow_cnames_no_type_match() {
        assert_eq!(
            None,
            follow_cnames(
                &[a_record("www.example.net", vec![1, 1, 1, 1])],
                &domain("www.example.com"),
                &QueryClass::Wildcard,
                &QueryType::Record(RecordType::NS)
            )
        );
    }

    #[test]
    fn follow_cnames_no_cname() {
        let rr_a = a_record("www.example.com", vec![127, 0, 0, 1]);
        assert_eq!(
            Some((domain("www.example.com"), HashMap::new())),
            follow_cnames(
                &[rr_a],
                &domain("www.example.com"),
                &QueryClass::Wildcard,
                &QueryType::Wildcard
            )
        );
    }

    #[test]
    fn follow_cnames_chain() {
        let rr_cname1 = cname_record("www.example.com", "www2.example.com");
        let rr_cname2 = cname_record("www2.example.com", "www3.example.com");
        let rr_a = a_record("www3.example.com", vec![127, 0, 0, 1]);

        let mut expected_map = HashMap::new();
        expected_map.insert(domain("www.example.com"), domain("www2.example.com"));
        expected_map.insert(domain("www2.example.com"), domain("www3.example.com"));

        // order of records does not matter, so pick the "worst"
        // order: the records are in the opposite order to what we'd
        // expect
        assert_eq!(
            Some((domain("www3.example.com"), expected_map)),
            follow_cnames(
                &[rr_a, rr_cname2, rr_cname1],
                &domain("www.example.com"),
                &QueryClass::Wildcard,
                &QueryType::Wildcard
            )
        );
    }

    #[test]
    fn follow_cnames_loop() {
        let rr_cname1 = cname_record("www.example.com", "bad.example.com");
        let rr_cname2 = cname_record("bad.example.com", "www.example.com");

        assert_eq!(
            None,
            follow_cnames(
                &[rr_cname1, rr_cname2],
                &domain("www.example.com"),
                &QueryClass::Wildcard,
                &QueryType::Wildcard
            )
        )
    }

    fn domain(name: &str) -> DomainName {
        DomainName::from_dotted_string(name).unwrap()
    }

    fn a_record(name: &str, octets: Vec<u8>) -> ResourceRecord {
        ResourceRecord {
            name: domain(name),
            rtype_with_data: RecordTypeWithData::Uninterpreted {
                rtype: RecordType::A,
                octets,
            },
            rclass: RecordClass::IN,
            ttl: 300,
        }
    }

    fn cname_record(name: &str, target_name: &str) -> ResourceRecord {
        ResourceRecord {
            name: domain(name),
            rtype_with_data: RecordTypeWithData::Named {
                rtype: RecordType::CNAME,
                name: domain(target_name),
            },
            rclass: RecordClass::IN,
            ttl: 300,
        }
    }
}
