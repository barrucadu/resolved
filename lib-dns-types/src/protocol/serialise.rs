//! Serialisation of DNS messages to the wire format.  See the `types`
//! module for details of the format.

use crate::protocol::types::*;

impl Message {
    /// # Errors
    ///
    /// If the message is invalid (the `Message` type permits more
    /// states than strictly allowed).
    pub fn to_octets(self) -> Result<Vec<u8>, Error> {
        let mut buffer = WritableBuffer::default();
        self.serialise(&mut buffer)?;
        Ok(buffer.octets)
    }

    /// # Errors
    ///
    /// If the message is invalid (the `Message` type permits more
    /// states than strictly allowed).
    pub fn serialise(self, buffer: &mut WritableBuffer) -> Result<(), Error> {
        let qdcount = usize_to_u16(self.questions.len())?;
        let ancount = usize_to_u16(self.answers.len())?;
        let nscount = usize_to_u16(self.authority.len())?;
        let arcount = usize_to_u16(self.additional.len())?;

        WireHeader {
            header: self.header,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
        .serialise(buffer);

        for question in self.questions {
            question.serialise(buffer);
        }
        for rr in self.answers {
            rr.serialise(buffer)?;
        }
        for rr in self.authority {
            rr.serialise(buffer)?;
        }
        for rr in self.additional {
            rr.serialise(buffer)?;
        }

        Ok(())
    }
}

impl WireHeader {
    pub fn serialise(self, buffer: &mut WritableBuffer) {
        // octet 1
        let flag_qr = if self.header.is_response {
            HEADER_MASK_QR
        } else {
            0
        };
        let field_opcode =
            HEADER_MASK_OPCODE & (u8::from(self.header.opcode) << HEADER_OFFSET_OPCODE);
        let flag_aa = if self.header.is_authoritative {
            HEADER_MASK_AA
        } else {
            0
        };
        let flag_tc = if self.header.is_truncated {
            HEADER_MASK_TC
        } else {
            0
        };
        let flag_rd = if self.header.recursion_desired {
            HEADER_MASK_RD
        } else {
            0
        };
        // octet 2
        let flag_ra = if self.header.recursion_available {
            HEADER_MASK_RA
        } else {
            0
        };
        let field_rcode = HEADER_MASK_RCODE & (u8::from(self.header.rcode) << HEADER_OFFSET_RCODE);

        buffer.write_u16(self.header.id);
        buffer.write_u8(flag_qr | field_opcode | flag_aa | flag_tc | flag_rd);
        buffer.write_u8(flag_ra | field_rcode);
        buffer.write_u16(self.qdcount);
        buffer.write_u16(self.ancount);
        buffer.write_u16(self.nscount);
        buffer.write_u16(self.arcount);
    }
}

impl Question {
    pub fn serialise(self, buffer: &mut WritableBuffer) {
        self.name.serialise(buffer);
        self.qtype.serialise(buffer);
        self.qclass.serialise(buffer);
    }
}

impl ResourceRecord {
    /// # Errors
    ///
    /// If the RDATA is too long.
    pub fn serialise(self, buffer: &mut WritableBuffer) -> Result<(), Error> {
        let (rtype, rdata) = match self.rtype_with_data {
            RecordTypeWithData::A { address } => (RecordType::A, Vec::from(address.octets())),
            RecordTypeWithData::NS { nsdname } => (RecordType::NS, nsdname.octets),
            RecordTypeWithData::MD { madname } => (RecordType::MD, madname.octets),
            RecordTypeWithData::MF { madname } => (RecordType::MF, madname.octets),
            RecordTypeWithData::CNAME { cname } => (RecordType::CNAME, cname.octets),
            RecordTypeWithData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let mut octets =
                    Vec::with_capacity(mname.octets.len() + rname.octets.len() + 4 + 4 + 4 + 4 + 4);
                for octet in mname.octets {
                    octets.push(octet);
                }
                for octet in rname.octets {
                    octets.push(octet);
                }
                for octet in serial.to_be_bytes() {
                    octets.push(octet);
                }
                for octet in refresh.to_be_bytes() {
                    octets.push(octet);
                }
                for octet in retry.to_be_bytes() {
                    octets.push(octet);
                }
                for octet in expire.to_be_bytes() {
                    octets.push(octet);
                }
                for octet in minimum.to_be_bytes() {
                    octets.push(octet);
                }
                (RecordType::SOA, octets)
            }
            RecordTypeWithData::MB { madname } => (RecordType::MB, madname.octets),
            RecordTypeWithData::MG { mdmname } => (RecordType::MG, mdmname.octets),
            RecordTypeWithData::MR { newname } => (RecordType::MR, newname.octets),
            RecordTypeWithData::NULL { octets } => (RecordType::NULL, octets),
            RecordTypeWithData::WKS { octets } => (RecordType::WKS, octets),
            RecordTypeWithData::PTR { ptrdname } => (RecordType::PTR, ptrdname.octets),
            RecordTypeWithData::HINFO { octets } => (RecordType::HINFO, octets),
            RecordTypeWithData::MINFO { rmailbx, emailbx } => {
                let mut octets = Vec::with_capacity(rmailbx.octets.len() + emailbx.octets.len());
                for octet in rmailbx.octets {
                    octets.push(octet);
                }
                for octet in emailbx.octets {
                    octets.push(octet);
                }
                (RecordType::MINFO, octets)
            }
            RecordTypeWithData::MX {
                preference,
                exchange,
            } => {
                let mut octets = Vec::with_capacity(2 + exchange.octets.len());
                for octet in preference.to_be_bytes() {
                    octets.push(octet);
                }
                for octet in exchange.octets {
                    octets.push(octet);
                }
                (RecordType::MX, octets)
            }
            RecordTypeWithData::TXT { octets } => (RecordType::TXT, octets),
            RecordTypeWithData::AAAA { address } => (RecordType::AAAA, Vec::from(address.octets())),
            RecordTypeWithData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                let mut octets = Vec::with_capacity(2 + 2 + 2 + target.octets.len());
                for octet in priority.to_be_bytes() {
                    octets.push(octet);
                }
                for octet in weight.to_be_bytes() {
                    octets.push(octet);
                }
                for octet in port.to_be_bytes() {
                    octets.push(octet);
                }
                for octet in target.octets {
                    octets.push(octet);
                }
                (RecordType::SRV, octets)
            }
            RecordTypeWithData::Unknown { tag, octets } => (RecordType::Unknown(tag), octets),
        };

        let rdlength = usize_to_u16(rdata.len())?;

        self.name.serialise(buffer);
        rtype.serialise(buffer);
        self.rclass.serialise(buffer);
        buffer.write_u32(self.ttl);
        buffer.write_u16(rdlength);
        buffer.write_octets(rdata);

        Ok(())
    }
}

impl DomainName {
    pub fn serialise(self, buffer: &mut WritableBuffer) {
        // TODO: implement compression - this'll need some extra state
        // in the WritableBuffer to keep track of previously-written
        // domains and labels.
        buffer.write_octets(self.octets);
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
    pub octets: Vec<u8>,
}

impl Default for WritableBuffer {
    fn default() -> Self {
        Self {
            octets: Vec::with_capacity(512),
        }
    }
}

impl WritableBuffer {
    pub fn write_u8(&mut self, octet: u8) {
        self.octets.push(octet);
    }

    pub fn write_u16(&mut self, value: u16) {
        for octet in value.to_be_bytes() {
            self.octets.push(octet);
        }
    }

    pub fn write_u32(&mut self, value: u32) {
        for octet in value.to_be_bytes() {
            self.octets.push(octet);
        }
    }

    pub fn write_octets(&mut self, octets: Vec<u8>) {
        for octet in octets {
            self.octets.push(octet);
        }
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
