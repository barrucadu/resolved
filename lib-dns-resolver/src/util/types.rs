use std::collections::HashSet;
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

/// A set of nameservers for a domain
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Nameservers {
    /// Guaranteed to be non-empty.
    ///
    /// TODO: find a non-empty-vec type
    pub hostnames: Vec<HostOrIP>,
    pub name: DomainName,
}

impl Nameservers {
    pub fn match_count(&self) -> usize {
        self.name.labels.len()
    }
}

/// A hostname or an IP
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum HostOrIP {
    Host(DomainName),
    IP(Ipv4Addr),
}

/// A response from a remote nameserver
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NameserverResponse {
    Answer {
        rrs: Vec<ResourceRecord>,
        is_authoritative: bool,
        authority_rrs: Vec<ResourceRecord>,
    },
    CNAME {
        rrs: Vec<ResourceRecord>,
        cname: DomainName,
        is_authoritative: bool,
    },
    Delegation {
        rrs: Vec<ResourceRecord>,
        delegation: Nameservers,
        is_authoritative: bool,
        authority_rrs: Vec<ResourceRecord>,
    },
}

impl From<NameserverResponse> for ResolvedRecord {
    fn from(nsr: NameserverResponse) -> Self {
        match nsr {
            NameserverResponse::Answer {
                is_authoritative: true,
                rrs,
                authority_rrs,
            } => ResolvedRecord::Authoritative { rrs, authority_rrs },
            NameserverResponse::Answer {
                is_authoritative: false,
                rrs,
                ..
            } => ResolvedRecord::NonAuthoritative { rrs },
            NameserverResponse::CNAME {
                rrs,
                is_authoritative,
                ..
            } => {
                if is_authoritative {
                    ResolvedRecord::Authoritative {
                        rrs,
                        authority_rrs: Vec::new(),
                    }
                } else {
                    ResolvedRecord::NonAuthoritative { rrs }
                }
            }
            NameserverResponse::Delegation {
                rrs,
                is_authoritative,
                authority_rrs,
                ..
            } => {
                if is_authoritative {
                    ResolvedRecord::Authoritative { rrs, authority_rrs }
                } else {
                    ResolvedRecord::NonAuthoritative { rrs }
                }
            }
        }
    }
}

/// An authoritative name error response, returned by the
/// non-recursive resolver.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AuthoritativeNameError {
    pub soa_rr: ResourceRecord,
}

impl From<AuthoritativeNameError> for ResolvedRecord {
    fn from(error: AuthoritativeNameError) -> Self {
        ResolvedRecord::AuthoritativeNameError {
            authority_rrs: vec![error.soa_rr],
        }
    }
}

impl From<Result<NameserverResponse, AuthoritativeNameError>> for ResolvedRecord {
    fn from(nsr_or_error: Result<NameserverResponse, AuthoritativeNameError>) -> Self {
        match nsr_or_error {
            Ok(nsr) => nsr.into(),
            Err(err) => err.into(),
        }
    }
}

/// Merge two sets of RRs, where records from the second set are
/// included if and only if there are no records of matching (name,
/// type) in the first set.
///
/// For example, if the first set is:
///
/// ```text
/// example.com. 300 IN A 1.1.1.1
/// example.com. 300 IN A 2.2.2.2
/// ```
///
/// And the second set is:
///
/// ```text
/// example.com. 300 IN A 3.3.3.3
/// example.net. 300 IN A 3.3.3.3
/// example.com. 300 IN MX mail.example.com.
/// ```
///
/// Then the output will be:
///
/// ```text
/// example.com. 300 IN A 1.1.1.1
/// example.com. 300 IN A 2.2.2.2
/// example.net. 300 IN A 3.3.3.3
/// example.com. 300 IN MX mail.example.com.
/// ```
///
/// Where the A records for `example.com.` have been dropped.  The
/// first set acts as an override of the second.
pub fn prioritising_merge(priority: &mut Vec<ResourceRecord>, new: Vec<ResourceRecord>) {
    let mut seen = HashSet::new();

    for rr in priority.iter() {
        seen.insert((rr.name.clone(), rr.rtype_with_data.rtype()));
    }

    for rr in new.into_iter() {
        if !seen.contains(&(rr.name.clone(), rr.rtype_with_data.rtype())) {
            priority.push(rr);
        }
    }
}

#[cfg(test)]
mod tests {
    use dns_types::protocol::types::test_util::*;

    use super::*;

    #[test]
    fn prioritised_merge_prioritises_by_name_and_type() {
        let mut priority = vec![
            a_record("www.example.com.", Ipv4Addr::new(1, 1, 1, 1)),
            a_record("www.example.com.", Ipv4Addr::new(2, 2, 2, 2)),
            cname_record("www.example.com.", "target.example.com."),
        ];
        let new = vec![
            a_record("www.example.com.", Ipv4Addr::new(3, 3, 3, 3)),
            a_record("www.example.net.", Ipv4Addr::new(4, 4, 4, 4)),
            cname_record("www.example.com.", "other-target.example.com."),
            ns_record("www.example.com.", "ns1.example.com."),
            ns_record("www.example.com.", "ns2.example.com."),
        ];

        prioritising_merge(&mut priority, new);
        priority.sort();

        let mut expected = vec![
            a_record("www.example.com.", Ipv4Addr::new(1, 1, 1, 1)),
            a_record("www.example.com.", Ipv4Addr::new(2, 2, 2, 2)),
            cname_record("www.example.com.", "target.example.com."),
            a_record("www.example.net.", Ipv4Addr::new(4, 4, 4, 4)),
            ns_record("www.example.com.", "ns1.example.com."),
            ns_record("www.example.com.", "ns2.example.com."),
        ];
        expected.sort();

        assert_eq!(expected, priority);
    }
}
