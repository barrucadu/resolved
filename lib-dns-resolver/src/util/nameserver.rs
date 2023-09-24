use rand::Rng;
use std::cmp::Ordering;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use dns_types::protocol::types::*;

use crate::util::net::{read_tcp_bytes, send_tcp_bytes, send_udp_bytes};

/// Send a message to a remote nameserver, preferring UDP if the request is
/// small enough.  If the request is too large, or if the UDP response is
/// truncated, tries again using TCP.
///
/// If an error occurs while sending the message or receiving the response, or
/// the response does not match the request, `None` is returned.
///
/// This has a 5s timeout for each request, so 10s in total.
pub async fn query_nameserver(
    address: SocketAddr,
    question: &Question,
    recursion_desired: bool,
) -> Option<Message> {
    let mut request = Message::from_question(rand::thread_rng().gen(), question.clone());
    request.header.recursion_desired = recursion_desired;

    match request.clone().into_octets() {
        Ok(mut serialised_request) => {
            tracing::trace!(message = ?request, ?address, "forwarding query to nameserver");

            if let Some(response) = query_nameserver_udp(address, &mut serialised_request).await {
                if response_matches_request(&request, &response) {
                    return Some(response);
                }
            }

            if let Some(response) = query_nameserver_tcp(address, &mut serialised_request).await {
                if response_matches_request(&request, &response) {
                    return Some(response);
                }
            }

            None
        }
        Err(error) => {
            tracing::warn!(message = ?request, ?error, "could not serialise message");
            None
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
    address: SocketAddr,
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
    address: SocketAddr,
    serialised_request: &mut [u8],
) -> Option<Message> {
    if serialised_request.len() > 512 {
        return None;
    }

    let mut buf = vec![0u8; 512];
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect(address).await.ok()?;
    send_udp_bytes(&sock, serialised_request).await.ok()?;
    sock.recv(&mut buf).await.ok()?;

    Message::from_octets(&buf).ok()
}

/// Send a message to a remote nameserver over TCP, returning the
/// response.  This has the same return value caveats as
/// `query_nameserver_udp`.
///
/// This has a 5s timeout.
pub async fn query_nameserver_tcp(
    address: SocketAddr,
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
    address: SocketAddr,
    serialised_request: &mut [u8],
) -> Option<Message> {
    let mut stream = TcpStream::connect(address).await.ok()?;
    send_tcp_bytes(&mut stream, serialised_request).await.ok()?;
    let bytes = read_tcp_bytes(&mut stream).await.ok()?;

    Message::from_octets(bytes.as_ref()).ok()
}

/// Very basic validation that a nameserver response matches a
/// message:
///
/// - Check the ID, opcode, and questions match the question.
///
/// - Check it is a response.
///
/// - Check the response code is either `NoError` or `NameError`.
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
    if !(response.header.rcode == Rcode::NoError || response.header.rcode == Rcode::NameError) {
        return false;
    }
    if request.questions != response.questions {
        return false;
    }

    true
}

/// Check if this is an NXDOMAIN or NODATA response and return the SOA if so.
///
/// Also sanity checks that the SOA record could be authoritative for the query
/// domain: the domain has to be a subdomain of the SOA, and the SOA has to have
/// at least the current match count.
pub fn get_nxdomain_nodata_soa(
    question: &Question,
    response: &Message,
    current_match_count: usize,
) -> Option<ResourceRecord> {
    if !response.answers.is_empty() {
        return None;
    }
    if !(response.header.rcode == Rcode::NameError || response.header.rcode == Rcode::NoError) {
        return None;
    }

    let mut soa_rr = None;
    for rr in &response.authority {
        if rr.rtype_with_data.rtype() == RecordType::SOA {
            // multiple SOAs: abort, abort!
            if soa_rr.is_some() {
                return None;
            }

            soa_rr = Some(rr);
        }
    }

    if let Some(rr) = soa_rr {
        if !question.name.is_subdomain_of(&rr.name) {
            return None;
        }

        if rr.name.labels.len().cmp(&current_match_count) == Ordering::Less {
            return None;
        }

        return Some(rr.clone());
    }

    None
}

#[cfg(test)]
mod tests {
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
}

#[cfg(test)]
pub mod test_util {
    use dns_types::protocol::types::test_util::*;
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
}
