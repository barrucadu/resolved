pub mod protocol;

use async_std::net::UdpSocket;
use async_std::task;

use crate::protocol::{ConsumableBuffer, Message};

async fn async_main() {
    let socket = UdpSocket::bind("127.0.0.1:53").await.expect("could not bind socket");
    let mut buf = vec![0u8; 512];

    loop {
        let (size, peer) = socket.recv_from(&mut buf).await.expect("error receiving data");
        println!("Message from {:?} ({} octets):", peer, size);
        println!("\t{:x?}", &buf[..size]);
        match Message::parse(&mut ConsumableBuffer::new(&buf[..size])) {
            Ok(msg) => println!("\t{:?}", msg),
            Err(err) => println!("\tcould not parse: {:?}", err),
        }
    }
}

fn main() {
    task::block_on(async_main());
}
