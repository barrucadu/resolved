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
        let qdcount = usize_to_counter(self.questions.len())?;
        let ancount = usize_to_counter(self.answers.len())?;
        let nscount = usize_to_counter(self.authority.len())?;
        let arcount = usize_to_counter(self.additional.len())?;

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
        let flags1 = (if self.header.is_response {
            0b1000_0000
        } else {
            0
        }) | (0b0111_1000 & (u8::from(self.header.opcode) << 3))
            | (if self.header.is_authoritative {
                0b0000_0100
            } else {
                0
            })
            | (if self.header.is_truncated {
                0b0000_0010
            } else {
                0
            })
            | (if self.header.recursion_desired {
                0b0000_0001
            } else {
                0
            });
        let flags2 = (if self.header.recursion_available {
            0b1000_0000
        } else {
            0
        }) | (0b0000_1111 & u8::from(self.header.rcode));

        buffer.write_u16(self.header.id);
        buffer.write_u8(flags1);
        buffer.write_u8(flags2);
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

        let rdlength = usize_to_counter(rdata.len())?;

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
    CounterTooLarge { counter: usize },
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

/// Helper function to convert a `usize` counter into the appropriate
/// width (or return an error)
///
/// # Errors
///
/// If the value cannot be converted.
fn usize_to_counter<T: TryFrom<usize>>(counter: usize) -> Result<T, Error> {
    if let Ok(t) = T::try_from(counter) {
        Ok(t)
    } else {
        Err(Error::CounterTooLarge { counter })
    }
}
