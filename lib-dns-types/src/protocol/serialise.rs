//! Serialisation of DNS messages to the wire format.  See the `types`
//! module for details of the format.

use bytes::{BufMut, BytesMut};
use std::collections::HashMap;

use crate::protocol::types::*;

impl Message {
    /// # Errors
    ///
    /// If the message is invalid (the `Message` type permits more
    /// states than strictly allowed).
    pub fn to_octets(&self) -> Result<BytesMut, Error> {
        let mut buffer = WritableBuffer::default();
        self.serialise(&mut buffer)?;
        Ok(buffer.octets)
    }

    /// # Errors
    ///
    /// If the message is invalid (the `Message` type permits more
    /// states than strictly allowed).
    pub fn serialise(&self, buffer: &mut WritableBuffer) -> Result<(), Error> {
        let qdcount = usize_to_u16(self.questions.len())?;
        let ancount = usize_to_u16(self.answers.len())?;
        let nscount = usize_to_u16(self.authority.len())?;
        let arcount = usize_to_u16(self.additional.len())?;

        self.header.serialise(buffer);
        buffer.write_u16(qdcount);
        buffer.write_u16(ancount);
        buffer.write_u16(nscount);
        buffer.write_u16(arcount);

        for question in &self.questions {
            question.serialise(buffer);
        }
        for rr in &self.answers {
            rr.serialise(buffer)?;
        }
        for rr in &self.authority {
            rr.serialise(buffer)?;
        }
        for rr in &self.additional {
            rr.serialise(buffer)?;
        }

        Ok(())
    }
}

impl Header {
    pub fn serialise(&self, buffer: &mut WritableBuffer) {
        // octet 1
        let flag_qr = if self.is_response { HEADER_MASK_QR } else { 0 };
        let field_opcode = HEADER_MASK_OPCODE & (u8::from(self.opcode) << HEADER_OFFSET_OPCODE);
        let flag_aa = if self.is_authoritative {
            HEADER_MASK_AA
        } else {
            0
        };
        let flag_tc = if self.is_truncated { HEADER_MASK_TC } else { 0 };
        let flag_rd = if self.recursion_desired {
            HEADER_MASK_RD
        } else {
            0
        };
        // octet 2
        let flag_ra = if self.recursion_available {
            HEADER_MASK_RA
        } else {
            0
        };
        let field_rcode = HEADER_MASK_RCODE & (u8::from(self.rcode) << HEADER_OFFSET_RCODE);

        buffer.write_u16(self.id);
        buffer.write_u8(flag_qr | field_opcode | flag_aa | flag_tc | flag_rd);
        buffer.write_u8(flag_ra | field_rcode);
    }
}

impl Question {
    pub fn serialise(&self, buffer: &mut WritableBuffer) {
        self.name.serialise(buffer, true);
        self.qtype.serialise(buffer);
        self.qclass.serialise(buffer);
    }
}

impl ResourceRecord {
    /// # Errors
    ///
    /// If the RDATA is too long.
    pub fn serialise(&self, buffer: &mut WritableBuffer) -> Result<(), Error> {
        self.name.serialise(buffer, true);
        self.rtype_with_data.rtype().serialise(buffer);
        self.rclass.serialise(buffer);
        buffer.write_u32(self.ttl);

        // filled in below
        let rdlength_index = buffer.index();
        buffer.write_u16(0);

        match &self.rtype_with_data {
            RecordTypeWithData::A { address } => buffer.write_octets(&address.octets()),
            RecordTypeWithData::NS { nsdname } => nsdname.serialise(buffer, false),
            RecordTypeWithData::MD { madname } => madname.serialise(buffer, false),
            RecordTypeWithData::MF { madname } => madname.serialise(buffer, false),
            RecordTypeWithData::CNAME { cname } => cname.serialise(buffer, false),
            RecordTypeWithData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                mname.serialise(buffer, false);
                rname.serialise(buffer, false);
                buffer.write_u32(*serial);
                buffer.write_u32(*refresh);
                buffer.write_u32(*retry);
                buffer.write_u32(*expire);
                buffer.write_u32(*minimum);
            }
            RecordTypeWithData::MB { madname } => madname.serialise(buffer, false),
            RecordTypeWithData::MG { mdmname } => mdmname.serialise(buffer, false),
            RecordTypeWithData::MR { newname } => newname.serialise(buffer, false),
            RecordTypeWithData::NULL { octets } => buffer.write_octets(octets),
            RecordTypeWithData::WKS { octets } => buffer.write_octets(octets),
            RecordTypeWithData::PTR { ptrdname } => ptrdname.serialise(buffer, false),
            RecordTypeWithData::HINFO { octets } => buffer.write_octets(octets),
            RecordTypeWithData::MINFO { rmailbx, emailbx } => {
                rmailbx.serialise(buffer, false);
                emailbx.serialise(buffer, false);
            }
            RecordTypeWithData::MX {
                preference,
                exchange,
            } => {
                buffer.write_u16(*preference);
                exchange.serialise(buffer, false);
            }
            RecordTypeWithData::TXT { octets } => buffer.write_octets(octets),
            RecordTypeWithData::AAAA { address } => buffer.write_octets(&address.octets()),
            RecordTypeWithData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                buffer.write_u16(*priority);
                buffer.write_u16(*weight);
                buffer.write_u16(*port);
                target.serialise(buffer, false);
            }
            RecordTypeWithData::Unknown { octets, .. } => buffer.write_octets(octets),
        };

        // -2 so we don't also include the 2 octets for the rdlength
        let rdlength = usize_to_u16(buffer.index() - rdlength_index - 2)?;
        let [hi, lo] = rdlength.to_be_bytes();
        buffer.octets[rdlength_index] = hi;
        buffer.octets[rdlength_index + 1] = lo;

        Ok(())
    }
}

impl DomainName {
    pub fn serialise(&self, buffer: &mut WritableBuffer, compress: bool) {
        if compress {
            if let Some(ptr) = buffer.name_pointer(self) {
                buffer.write_u16(ptr);
                return;
            }
        }

        buffer.memoise_name(self);
        for label in &self.labels {
            buffer.write_u8(label.len());
            buffer.write_octets(&label.octets);
        }
    }
}

impl QueryType {
    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.into());
    }
}

impl QueryClass {
    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.into());
    }
}

impl RecordType {
    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.into());
    }
}

impl RecordClass {
    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.into());
    }
}

/// Errors encountered when serialising a message.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Error {
    /// A counter does not fit in the desired width.
    CounterTooLarge { counter: usize, bits: u32 },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::CounterTooLarge { counter, bits } => {
                write!(f, "'{counter}' cannot be converted to a u{bits}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// A buffer which can be written to, for serialisation purposes.
pub struct WritableBuffer {
    pub octets: BytesMut,
    name_pointers: HashMap<DomainName, u16>,
}

impl Default for WritableBuffer {
    fn default() -> Self {
        Self {
            octets: BytesMut::with_capacity(512),
            name_pointers: HashMap::new(),
        }
    }
}

impl WritableBuffer {
    pub fn index(&self) -> usize {
        self.octets.len()
    }

    pub fn memoise_name(&mut self, name: &DomainName) {
        if !name.is_root() && !self.name_pointers.contains_key(name) {
            if let Ok(index) = u16::try_from(self.index()) {
                let [hi, lo] = index.to_be_bytes();
                self.name_pointers
                    .insert(name.clone(), u16::from_be_bytes([hi | 0b1100_0000, lo]));
            }
        }
    }

    pub fn name_pointer(&self, name: &DomainName) -> Option<u16> {
        self.name_pointers.get(name).copied()
    }

    pub fn write_u8(&mut self, octet: u8) {
        self.octets.put_u8(octet);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.write_octets(&value.to_be_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.write_octets(&value.to_be_bytes());
    }

    pub fn write_octets(&mut self, octets: &[u8]) {
        self.octets.put_slice(octets);
    }
}

/// Helper function to convert a `usize` into a `u16` (or return an error).
///
/// # Errors
///
/// If the value cannot be converted.
fn usize_to_u16(counter: usize) -> Result<u16, Error> {
    if let Ok(t) = u16::try_from(counter) {
        Ok(t)
    } else {
        Err(Error::CounterTooLarge {
            counter,
            bits: u16::BITS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::types::test_util::*;

    #[test]
    #[rustfmt::skip]
    fn test_name_compression_opt_in() {
        let mut buf = WritableBuffer::default();
        buf.write_u8(1);
        buf.write_u8(2);
        buf.write_u8(3);
        buf.write_u8(4);
        domain("www.example.com.").serialise(&mut buf, true);
        domain("www.example.com.").serialise(&mut buf, true);

        assert_eq!(
            vec![
                1, 2, 3, 4,
                // domain 1
                3, 119, 119, 119, // "www"
                7, 101, 120, 97, 109, 112, 108, 101, // "example"
                3, 99, 111, 109, 0, // "com"
                // domain 2
                0b1100_0000, 0b0000_0100 // pointer
            ],
            buf.octets,
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_name_compression_opt_out() {
        let mut buf = WritableBuffer::default();
        buf.write_u8(1);
        buf.write_u8(2);
        buf.write_u8(3);
        buf.write_u8(4);
        domain("www.example.com.").serialise(&mut buf, true);
        domain("www.example.com.").serialise(&mut buf, false);

        assert_eq!(
            vec![
                1, 2, 3, 4,
                // domain 1
                3, 119, 119, 119, // "www"
                7, 101, 120, 97, 109, 112, 108, 101, // "example"
                3, 99, 111, 109, 0, // "com"
                // domain 2
                3, 119, 119, 119, // "www"
                7, 101, 120, 97, 109, 112, 108, 101, // "example"
                3, 99, 111, 109, 0, // "com"
            ],
            buf.octets,
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_name_compression_records() {
        let mut buf = WritableBuffer::default();
        buf.write_u8(1);
        buf.write_u8(2);
        buf.write_u8(3);
        buf.write_u8(4);

        Question {
            name: domain("www.example.com."),
            qtype: QueryType::Wildcard,
            qclass: QueryClass::Wildcard,
        }.serialise(&mut buf);

        let _ = ResourceRecord {
            name: domain("www.example.com."),
            rtype_with_data: RecordTypeWithData::MX {
                preference: 32,
                exchange: domain("mx.example.com."),
            },
            rclass: RecordClass::IN,
            ttl: 300,
        }.serialise(&mut buf);

        let _ = ResourceRecord {
            name: domain("mx.example.com."),
            rtype_with_data: RecordTypeWithData::CNAME {
                cname: domain("www.example.com."),
            },
            rclass: RecordClass::IN,
            ttl: 300,
        }.serialise(&mut buf);

        assert_eq!(
            vec![
                1, 2, 3, 4,
                // QNAME
                3, 119, 119, 119, // "www"
                7, 101, 120, 97, 109, 112, 108, 101, // "example"
                3, 99, 111, 109, 0, // "com"
                // QTYPE
                0, 255,
                // QCLASS
                0, 255,
                // NAME
                0b1100_0000, 0b0000_0100, // pointer to "www.example.com"
                // TYPE
                0b0000_0000, 0b0000_1111, // MX
                // CLASS
                0b0000_0000, 0b0000_0001, // IN
                // TTL
                0b0000_0000, 0b0000_0000, 0b0000_0001, 0b0010_1100, // 300
                // RDLENGTH
                0b0000_0000, 0b0001_0010, // 18 octets
                // RDATA
                0, 32, // preference
                2, 109, 120, // "mx"
                7, 101, 120, 97, 109, 112, 108, 101, // "example"
                3, 99, 111, 109, 0, // "com"
                // NAME
                0b1100_0000, 0b0010_0111, // pointer to "mx.example.com"
                // TYPE
                0b0000_0000, 0b0000_0101, // CNAME
                // CLASS
                0b0000_0000, 0b0000_0001, // IN
                // TTL
                0b0000_0000, 0b0000_0000, 0b0000_0001, 0b0010_1100, // 300
                // RDLENGTH
                0b0000_0000, 0b0001_0001, // 17 octets
                // RDATA
                3, 119, 119, 119, // "www"
                7, 101, 120, 97, 109, 112, 108, 101, // "example"
                3, 99, 111, 109, 0, // "com"
            ],
            buf.octets,
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_sets_rdlength() {
        let mut buf = WritableBuffer::default();
        buf.write_u8(1);
        buf.write_u8(2);
        buf.write_u8(3);
        buf.write_u8(4);

        let rr = ResourceRecord {
            name: domain("www.example.com."),
            rtype_with_data: RecordTypeWithData::MX {
                preference: 32,
                exchange: domain("mx.example.com."),
            },
            rclass: RecordClass::IN,
            ttl: 300,
        };
        let _ = rr.serialise(&mut buf);

        assert_eq!(
            vec![
                1, 2, 3, 4,
                // NAME
                3, 119, 119, 119, // "www"
                7, 101, 120, 97, 109, 112, 108, 101, // "example"
                3, 99, 111, 109, 0, // "com"
                // TYPE
                0b0000_0000, 0b0000_1111, // MX
                // CLASS
                0b0000_0000, 0b0000_0001, // IN
                // TTL
                0b0000_0000, 0b0000_0000, 0b0000_0001, 0b0010_1100, // 300
                // RDLENGTH
                0b0000_0000, 0b0001_0010, // 18 octets
                // RDATA
                0, 32, // preference
                2, 109, 120, // "mx"
                7, 101, 120, 97, 109, 112, 108, 101, // "example"
                3, 99, 111, 109, 0, // "com"
            ],
            buf.octets,
        );
    }
}
