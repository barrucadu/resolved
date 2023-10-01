use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use dns_types::protocol::types::*;

pub const CANNOT_PARSE_PROTOCOL_MODE: &str =
    "expected one of 'only-v4', 'prefer-v4', 'prefer-v6', 'only'v6'";

/// How the recursive resolver should choose which IP address to try for
/// upstream nameservers.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ProtocolMode {
    /// Only use IPv4 (e.g. this is an IPv4-only network), rejecting a
    /// nameserver if it is only available over IPv6.
    OnlyV4,
    /// If a nameserver is only available over IPv6, use that; but if it is
    /// available over both IPv4 and IPv6 (or only IPv4), use the IPv4 address.
    PreferV4,
    /// If a nameserver is only available over IPv4, use that; but if it is
    /// available over both IPv4 and IPv6 (or only IPv6), use the IPv6 address.
    PreferV6,
    /// Only use IPv6 (e.g. this is an IPv6-only network), rejecting a
    /// nameserver if it is only available over IPv4.
    OnlyV6,
}

impl fmt::Display for ProtocolMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProtocolMode::OnlyV4 => write!(f, "only-v4"),
            ProtocolMode::PreferV4 => write!(f, "prefer-v4"),
            ProtocolMode::PreferV6 => write!(f, "prefer-v6"),
            ProtocolMode::OnlyV6 => write!(f, "only-v6"),
        }
    }
}

impl FromStr for ProtocolMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "only-v4" => Ok(ProtocolMode::OnlyV4),
            "prefer-v4" => Ok(ProtocolMode::PreferV4),
            "prefer-v6" => Ok(ProtocolMode::PreferV6),
            "only-v6" => Ok(ProtocolMode::OnlyV6),
            _ => Err(CANNOT_PARSE_PROTOCOL_MODE),
        }
    }
}

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
        soa_rr: ResourceRecord,
    },
    AuthoritativeNameError {
        soa_rr: ResourceRecord,
    },
    NonAuthoritative {
        rrs: Vec<ResourceRecord>,
        soa_rr: Option<ResourceRecord>,
    },
}

impl ResolvedRecord {
    pub fn rrs(self) -> Vec<ResourceRecord> {
        match self {
            ResolvedRecord::Authoritative { rrs, .. } => rrs,
            ResolvedRecord::AuthoritativeNameError { .. } => Vec::new(),
            ResolvedRecord::NonAuthoritative { rrs, .. } => rrs,
        }
    }

    pub fn soa_rr(&self) -> Option<&ResourceRecord> {
        match self {
            ResolvedRecord::Authoritative { soa_rr, .. } => Some(soa_rr),
            ResolvedRecord::AuthoritativeNameError { soa_rr } => Some(soa_rr),
            ResolvedRecord::NonAuthoritative { soa_rr, .. } => soa_rr.into(),
        }
    }
}

/// An error that can occur when trying to resolve a domain.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ResolutionError {
    /// Recursive or forwarding resolution timed out and was aborted.
    Timeout,
    /// Hit the recursion limit while following CNAMEs.
    RecursionLimit,
    /// Tried to resolve a question while resolving the same question.
    DuplicateQuestion { question: Question },
    /// Was unable to resolve a necessary record.
    DeadEnd { question: Question },
    /// Configuration error: a local zone delegates without defining NS records.
    LocalDelegationMissingNS {
        apex: DomainName,
        domain: DomainName,
    },
    /// Internal error: got a result from the cache which doesn't match the
    /// querytype.
    CacheTypeMismatch {
        query: QueryType,
        result: RecordType,
    },
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ResolutionError::Timeout => write!(f, "timed out"),
            ResolutionError::RecursionLimit => write!(f, "CNAME chain too long"),
            ResolutionError::DuplicateQuestion{question} => write!(f, "loop when answering '{} {} {}'", question.name, question.qclass, question.qtype),
            ResolutionError::DeadEnd{question} => write!(f, "unable to answer '{} {} {}'", question.name, question.qclass, question.qtype),
            ResolutionError::LocalDelegationMissingNS{apex,domain} => write!(f, "configuration error: got delegation for domain '{domain}' from zone '{apex}', but there are no NS records"),
            ResolutionError::CacheTypeMismatch{query,result} => write!(f, "internal error (bug): tried to fetch '{query}' from cache but got '{result}' instead"),
        }
    }
}

impl std::error::Error for ResolutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// A set of nameservers for a domain
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Nameservers {
    /// Guaranteed to be non-empty.
    ///
    /// TODO: find a non-empty-vec type
    pub hostnames: Vec<DomainName>,
    pub name: DomainName,
}

impl Nameservers {
    pub fn match_count(&self) -> usize {
        self.name.labels.len()
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

    for rr in &*priority {
        seen.insert((rr.name.clone(), rr.rtype_with_data.rtype()));
    }

    for rr in new {
        if !seen.contains(&(rr.name.clone(), rr.rtype_with_data.rtype())) {
            priority.push(rr);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

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
