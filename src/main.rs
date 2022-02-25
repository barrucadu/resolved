pub mod protocol;

use tokio::net::UdpSocket;

use crate::protocol::{ConsumableBuffer, Message, ProtocolError};

#[tokio::main]
async fn main() {
    let socket = UdpSocket::bind("127.0.0.1:53")
        .await
        .expect("could not bind socket");
    let mut buf = vec![0u8; 512];

    loop {
        let (size, peer) = socket
            .recv_from(&mut buf)
            .await
            .expect("error receiving data");

        println!("Message from {:?} ({} octets):", peer, size);
        println!("\t{:x?}", &buf[..size]);

        match Message::parse(&mut ConsumableBuffer::new(&buf[..size])) {
            Ok(msg) => {
                println!("\t{:?}", msg);

                let mut response = Message::make_response(msg);
                response.header.rcode = protocol::Rcode::NotImplemented;
                socket
                    .send_to(response.serialise_for_udp().as_slice(), peer)
                    .await
                    .expect("error sending data");
            }
            Err(err @ ProtocolError::HeaderTooShort(id))
            | Err(err @ ProtocolError::QuestionTooShort(id))
            | Err(err @ ProtocolError::ResourceRecordTooShort(id))
            | Err(err @ ProtocolError::DomainTooShort(id))
            | Err(err @ ProtocolError::DomainTooLong(id))
            | Err(err @ ProtocolError::DomainLabelInvalid(id))
            | Err(err @ ProtocolError::UnknownQueryType(id))
            | Err(err @ ProtocolError::UnknownQueryClass(id))
            | Err(err @ ProtocolError::UnknownRecordType(id))
            | Err(err @ ProtocolError::UnknownRecordClass(id)) => {
                println!("\tcould not parse: {:?}!", err);

                let response = Message::make_format_error_response(id);
                socket
                    .send_to(response.serialise_for_udp().as_slice(), peer)
                    .await
                    .expect("error sending data");
            }
            Err(ProtocolError::CompletelyBusted) => {
                println!("\tcompletely busted - cannot send response!");
            }
        }
    }
}
