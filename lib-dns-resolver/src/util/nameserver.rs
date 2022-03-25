use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use dns_types::protocol::types::*;

use crate::util::net::{read_tcp_bytes, send_tcp_bytes, send_udp_bytes};

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
