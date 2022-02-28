use bytes::BytesMut;
use std::io;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

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
