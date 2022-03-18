use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use dns_types::protocol::types::*;

use crate::net_util::{read_tcp_bytes, send_tcp_bytes, send_udp_bytes};

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
            NameserverResponse::CNAME { .. } => todo!(),
            NameserverResponse::Delegation { .. } => todo!(),
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

/// Send a message to a remote nameserver over UDP, returning the
/// response.  If the message would be truncated, or an error occurs
/// while sending it, `None` is returned.  Otherwise the deserialised
/// response message is: but this response is NOT validated -
/// consumers MUST validate the response before using it!
///
/// This has a 5s timeout.
pub async fn query_nameserver_udp(
    address: Ipv4Addr,
    serialised_request: &mut [u8],
) -> Option<Message> {
    match timeout(
        Duration::from_secs(5),
        query_nameserver_udp_notimeout(address, serialised_request),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => None,
    }
}

/// Timeout-less version of `query_nameserver_udp`.
async fn query_nameserver_udp_notimeout(
    address: Ipv4Addr,
    serialised_request: &mut [u8],
) -> Option<Message> {
    if serialised_request.len() > 512 {
        return None;
    }

    let mut buf = vec![0u8; 512];
    match UdpSocket::bind("0.0.0.0:0").await {
        Ok(sock) => match sock.connect((address, 53)).await {
            Ok(_) => match send_udp_bytes(&sock, serialised_request).await {
                Ok(_) => match sock.recv(&mut buf).await {
                    Ok(_) => match Message::from_octets(&buf) {
                        Ok(response) => Some(response),
                        _ => None,
                    },
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// Send a message to a remote nameserver over TCP, returning the
/// response.  This has the same return value caveats as
/// `query_nameserver_udp`.
///
/// This has a 5s timeout.
pub async fn query_nameserver_tcp(
    address: Ipv4Addr,
    serialised_request: &mut [u8],
) -> Option<Message> {
    match timeout(
        Duration::from_secs(5),
        query_nameserver_tcp_notimeout(address, serialised_request),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => None,
    }
}

/// Timeout-less version of `query_nameserver_tcp`.
async fn query_nameserver_tcp_notimeout(
    address: Ipv4Addr,
    serialised_request: &mut [u8],
) -> Option<Message> {
    match TcpStream::connect((address, 53)).await {
        Ok(mut stream) => match send_tcp_bytes(&mut stream, serialised_request).await {
            Ok(_) => match read_tcp_bytes(&mut stream).await {
                Ok(bytes) => match Message::from_octets(bytes.as_ref()) {
                    Ok(response) => Some(response),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// Very basic validation that a nameserver response matches a
/// message:
///
/// - Check the ID, opcode, and questions match the question.
///
/// - Check it is a response and no error is signalled.
///
/// - Check it is not truncated.
pub fn response_matches_request(request: &Message, response: &Message) -> bool {
    if request.header.id != response.header.id {
        return false;
    }
    if !response.header.is_response {
        return false;
    }
    if request.header.opcode != response.header.opcode {
        return false;
    }
    if response.header.is_truncated {
        return false;
    }
    if response.header.rcode != Rcode::NoError {
        return false;
    }
    if request.questions != response.questions {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use dns_types::protocol::types::test_util::*;

    use super::test_util::*;
    use super::*;

    #[test]
    fn response_matches_request_accepts() {
        let (request, response) = matching_nameserver_response();

        assert!(response_matches_request(&request, &response));
    }

    #[test]
    fn response_matches_request_checks_id() {
        let (request, mut response) = matching_nameserver_response();
        response.header.id += 1;

        assert!(!response_matches_request(&request, &response));
    }

    #[test]
    fn response_matches_request_checks_qr() {
        let (request, mut response) = matching_nameserver_response();
        response.header.is_response = false;

        assert!(!response_matches_request(&request, &response));
    }

    #[test]
    fn response_matches_request_checks_opcode() {
        let (request, mut response) = matching_nameserver_response();
        response.header.opcode = Opcode::Status;

        assert!(!response_matches_request(&request, &response));
    }

    #[test]
    fn response_matches_request_does_not_check_aa() {
        let (request, mut response) = matching_nameserver_response();
        response.header.is_authoritative = !response.header.is_authoritative;

        assert!(response_matches_request(&request, &response));
    }

    #[test]
    fn response_matches_request_checks_tc() {
        let (request, mut response) = matching_nameserver_response();
        response.header.is_truncated = true;

        assert!(!response_matches_request(&request, &response));
    }

    #[test]
    fn response_matches_request_does_not_check_rd() {
        let (request, mut response) = matching_nameserver_response();
        response.header.recursion_desired = !response.header.recursion_desired;

        assert!(response_matches_request(&request, &response));
    }

    #[test]
    fn response_matches_request_does_not_check_ra() {
        let (request, mut response) = matching_nameserver_response();
        response.header.recursion_available = !response.header.recursion_available;

        assert!(response_matches_request(&request, &response));
    }

    #[test]
    fn response_matches_request_checks_rcode() {
        let (request, mut response) = matching_nameserver_response();
        response.header.rcode = Rcode::ServerFailure;

        assert!(!response_matches_request(&request, &response));
    }

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

#[cfg(test)]
pub mod test_util {
    use dns_types::protocol::types::test_util::*;
    use dns_types::zones::types::*;
    use std::net::Ipv4Addr;

    use super::*;

    pub fn matching_nameserver_response() -> (Message, Message) {
        nameserver_response(
            "www.example.com.",
            &[a_record("www.example.com.", Ipv4Addr::new(1, 1, 1, 1))],
            &[],
            &[],
        )
    }

    pub fn nameserver_response(
        name: &str,
        answers: &[ResourceRecord],
        authority: &[ResourceRecord],
        additional: &[ResourceRecord],
    ) -> (Message, Message) {
        let request = Message::from_question(
            1234,
            Question {
                name: domain(name),
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Record(RecordClass::IN),
            },
        );

        let mut response = request.make_response();
        response.answers = answers.into();
        response.authority = authority.into();
        response.additional = additional.into();

        (request, response)
    }

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
        zone_na.insert(
            &domain("trailing-cname.example.com."),
            RecordTypeWithData::CNAME {
                cname: domain("somewhere-else.example.com."),
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
