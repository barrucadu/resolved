use bytes::BytesMut;
use std::io;
use std::net::SocketAddr;
use std::process;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing;

/// Read a DNS message from a TCP stream.
///
/// A DNS TCP message is slightly different to a DNS UDP message: it
/// has a big-endian u16 prefix giving the total length of the
/// message.  This is redundant (since the header is fixed-size and
/// says how many fields there are, and the fields contain length
/// information), but it means the entire message can be read before
/// parsing begins.
pub async fn read_tcp_bytes(stream: &mut TcpStream) -> Result<BytesMut, TcpError> {
    match stream.read_u16().await {
        Ok(size) => {
            let expected = size as usize;
            let mut bytes = BytesMut::with_capacity(expected);
            while bytes.len() < expected {
                match stream.read_buf(&mut bytes).await {
                    Ok(0) if bytes.len() < expected => {
                        let id = if bytes.len() >= 2 {
                            Some(u16::from_be_bytes([bytes[0], bytes[1]]))
                        } else {
                            None
                        };
                        return Err(TcpError::TooShort {
                            id,
                            expected,
                            actual: bytes.len(),
                        });
                    }
                    Err(err) => {
                        let id = if bytes.len() >= 2 {
                            Some(u16::from_be_bytes([bytes[0], bytes[1]]))
                        } else {
                            None
                        };
                        return Err(TcpError::IO { id, error: err });
                    }
                    _ => (),
                }
            }
            Ok(bytes)
        }
        Err(err) => Err(TcpError::IO {
            id: None,
            error: err,
        }),
    }
}

/// An error that can occur when reading a DNS TCP message.
#[derive(Debug)]
pub enum TcpError {
    TooShort {
        id: Option<u16>,
        expected: usize,
        actual: usize,
    },
    IO {
        id: Option<u16>,
        error: io::Error,
    },
}

/// Write a serialised message to a UDP channel.  This sets or clears
/// the TC flag as appropriate.
pub async fn send_udp_bytes(sock: &UdpSocket, bytes: &mut [u8]) -> Result<(), io::Error> {
    if bytes.len() < 12 {
        tracing::error!(length = %bytes.len(), "message too short");
        process::exit(1);
    }

    if bytes.len() > 512 {
        bytes[2] |= 0b00000010;
        sock.send(&bytes[..512]).await?;
    } else {
        bytes[2] &= 0b11111101;
        sock.send(bytes).await?;
    }

    Ok(())
}

/// Like `send_udp_bytes` but sends to the given address
pub async fn send_udp_bytes_to(
    sock: &UdpSocket,
    target: SocketAddr,
    bytes: &mut [u8],
) -> Result<(), io::Error> {
    // TODO: see if this can be combined with `send_udp_bytes`

    if bytes.len() < 12 {
        tracing::error!(length = %bytes.len(), "message too short");
        process::exit(1);
    }

    if bytes.len() > 512 {
        bytes[2] |= 0b00000010;
        sock.send_to(&bytes[..512], target).await?;
    } else {
        bytes[2] &= 0b11111101;
        sock.send_to(bytes, target).await?;
    }

    Ok(())
}

/// Write a serialised message to a TCP channel.  This sends a
/// two-byte length prefix (big-endian u16) and sets or clears the TC
/// flag as appropriate.
pub async fn send_tcp_bytes(stream: &mut TcpStream, bytes: &mut [u8]) -> Result<(), io::Error> {
    if bytes.len() < 12 {
        tracing::error!(length = %bytes.len(), "message too short");
        process::exit(1);
    }

    let len = if let Ok(len) = bytes.len().try_into() {
        bytes[2] &= 0b11111101;
        len
    } else {
        bytes[2] |= 0b00000010;
        u16::MAX
    };

    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&bytes[..(len as usize)]).await?;

    Ok(())
}
