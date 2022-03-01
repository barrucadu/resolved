//! Deserialisation of DNS messages from the network.  See the
//! `wire_types` module for details of the format.

use crate::protocol::wire_types::*;

impl Message {
    pub fn from_octets(octets: &[u8]) -> Result<Self, ProtocolError> {
        Self::deserialise(&mut ConsumableBuffer::new(octets))
    }

    pub fn deserialise(buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let header = Header::deserialise(buffer)?;
        let mut questions = Vec::with_capacity(header.qdcount.into());
        let mut answers = Vec::with_capacity(header.ancount.into());
        let mut authority = Vec::with_capacity(header.nscount.into());
        let mut additional = Vec::with_capacity(header.arcount.into());

        for _ in 0..header.qdcount {
            questions.push(Question::deserialise(header.id, buffer)?);
        }
        for _ in 0..header.ancount {
            answers.push(ResourceRecord::deserialise(header.id, buffer)?);
        }
        for _ in 0..header.nscount {
            authority.push(ResourceRecord::deserialise(header.id, buffer)?);
        }
        for _ in 0..header.arcount {
            additional.push(ResourceRecord::deserialise(header.id, buffer)?);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }
}

impl Header {
    pub fn deserialise(buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let id = buffer.next_u16().ok_or(ProtocolError::CompletelyBusted)?;
        let flags1 = buffer.next_u8().ok_or(ProtocolError::HeaderTooShort(id))?;
        let flags2 = buffer.next_u8().ok_or(ProtocolError::HeaderTooShort(id))?;
        let qdcount = buffer.next_u16().ok_or(ProtocolError::HeaderTooShort(id))?;
        let ancount = buffer.next_u16().ok_or(ProtocolError::HeaderTooShort(id))?;
        let nscount = buffer.next_u16().ok_or(ProtocolError::HeaderTooShort(id))?;
        let arcount = buffer.next_u16().ok_or(ProtocolError::HeaderTooShort(id))?;

        Ok(Self {
            id,
            is_response: flags1 & 0b10000000 != 0,
            opcode: Opcode::from((flags1 & 0b01111000) >> 3),
            is_authoritative: flags1 & 0b00000100 != 0,
            is_truncated: flags1 & 0b00000010 != 0,
            recursion_desired: flags1 & 0b00000001 != 0,
            recursion_available: flags2 & 0b10000000 != 0,
            rcode: Rcode::from(flags2 & 0b00001111),
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }
}

impl Question {
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let name = DomainName::deserialise(id, buffer)?;
        let qtype = QueryType::deserialise(id, buffer)?;
        let qclass = QueryClass::deserialise(id, buffer)?;

        Ok(Self {
            name,
            qtype,
            qclass,
        })
    }
}

impl ResourceRecord {
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let name = DomainName::deserialise(id, buffer)?;
        let rtype = RecordType::deserialise(id, buffer)?;
        let rclass = RecordClass::deserialise(id, buffer)?;
        let ttl = buffer
            .next_u32()
            .ok_or(ProtocolError::ResourceRecordTooShort(id))?;
        let rdlength = buffer
            .next_u16()
            .ok_or(ProtocolError::ResourceRecordTooShort(id))?;

        // for records which include domain names, deserialise them to
        // expand pointers.
        let rtype_with_data = match rtype {
            RecordType::CNAME
            | RecordType::MB
            | RecordType::MD
            | RecordType::MF
            | RecordType::MG
            | RecordType::MR
            | RecordType::NS
            | RecordType::PTR => RecordTypeWithData::Named {
                rtype,
                name: DomainName::deserialise(id, buffer)?,
            },

            RecordType::MINFO => RecordTypeWithData::MINFO {
                rmailbx: DomainName::deserialise(id, buffer)?,
                emailbx: DomainName::deserialise(id, buffer)?,
            },

            RecordType::MX => RecordTypeWithData::MX {
                preference: buffer
                    .next_u16()
                    .ok_or(ProtocolError::ResourceRecordTooShort(id))?,
                exchange: DomainName::deserialise(id, buffer)?,
            },

            RecordType::SOA => RecordTypeWithData::SOA {
                mname: DomainName::deserialise(id, buffer)?,
                rname: DomainName::deserialise(id, buffer)?,
                serial: buffer
                    .next_u32()
                    .ok_or(ProtocolError::ResourceRecordTooShort(id))?,
                refresh: buffer
                    .next_u32()
                    .ok_or(ProtocolError::ResourceRecordTooShort(id))?,
                retry: buffer
                    .next_u32()
                    .ok_or(ProtocolError::ResourceRecordTooShort(id))?,
                expire: buffer
                    .next_u32()
                    .ok_or(ProtocolError::ResourceRecordTooShort(id))?,
                minimum: buffer
                    .next_u32()
                    .ok_or(ProtocolError::ResourceRecordTooShort(id))?,
            },

            _ => {
                if let Some(octets) = buffer.take(rdlength as usize) {
                    RecordTypeWithData::Uninterpreted {
                        rtype,
                        octets: octets.to_vec(),
                    }
                } else {
                    return Err(ProtocolError::ResourceRecordTooShort(id));
                }
            }
        };

        Ok(Self {
            name,
            rtype_with_data,
            rclass,
            ttl,
        })
    }
}

impl DomainName {
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let mut octets = Vec::<u8>::with_capacity(255);
        let mut labels = Vec::<Vec<u8>>::with_capacity(5);
        let start = buffer.position;

        'outer: loop {
            let size = buffer.next_u8().ok_or(ProtocolError::DomainTooShort(id))?;

            if size <= 63 {
                let mut label = Vec::with_capacity(size.into());
                octets.push(size);

                if size == 0 {
                    labels.push(label);
                    break 'outer;
                }

                if let Some(os) = buffer.take(size as usize) {
                    for o in os {
                        let lowered = o.to_ascii_lowercase();
                        octets.push(lowered);
                        label.push(lowered);
                    }
                } else {
                    return Err(ProtocolError::DomainTooShort(id));
                }

                labels.push(label);

                if octets.len() > 255 {
                    break 'outer;
                }
            } else if size >= 192 {
                // this requires re-parsing the pointed-to domain -
                // not great but works for now.
                let hi = size & 0b00111111;
                let lo = buffer.next_u8().ok_or(ProtocolError::DomainTooShort(id))?;
                let ptr = u16::from_be_bytes([hi, lo]).into();

                // pointer must be to an earlier record (not merely a
                // different one: an earlier one: RFC 1035 section
                // 4.1.4)
                if ptr >= start {
                    return Err(ProtocolError::DomainPointerInvalid(id));
                }

                let mut other = DomainName::deserialise(id, &mut buffer.at_offset(ptr))?;
                octets.append(&mut other.octets);
                labels.append(&mut other.labels);
                break 'outer;
            } else {
                return Err(ProtocolError::DomainLabelInvalid(id));
            }
        }

        if octets.len() <= 255 {
            Ok(DomainName { octets, labels })
        } else {
            Err(ProtocolError::DomainTooLong(id))
        }
    }
}

impl QueryType {
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::QuestionTooShort(id))?;
        Ok(Self::from(value))
    }
}

impl QueryClass {
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::QuestionTooShort(id))?;
        Ok(Self::from(value))
    }
}

impl RecordType {
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::ResourceRecordTooShort(id))?;
        Ok(Self::from(value))
    }
}

impl RecordClass {
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::ResourceRecordTooShort(id))?;
        Ok(Self::from(value))
    }
}

/// Errors encountered when parsing a datagram.  In all the errors
/// which have a `u16` parameter, that is the ID from the header - so
/// that an error response can be sent.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ProtocolError {
    /// The datagram is not even 2 octets long, so it doesn't even
    /// contain a valid ID.  An error cannot even be sent back to the
    /// client in this case as, without an ID, it cannot be linked
    /// with the correct query.
    CompletelyBusted,

    /// The header is missing one or more required fields.
    HeaderTooShort(u16),

    /// A question ends with an incomplete field.
    QuestionTooShort(u16),

    /// A resource record ends with an incomplete field.
    ResourceRecordTooShort(u16),

    /// A domain is incomplete.
    DomainTooShort(u16),

    /// A domain is over 255 octets in size.
    DomainTooLong(u16),

    /// A domain pointer points to or after the current record.
    DomainPointerInvalid(u16),

    /// A domain label is longer than 63 octets, but not a pointer.
    DomainLabelInvalid(u16),
}

impl ProtocolError {
    pub fn id(self) -> Option<u16> {
        match self {
            ProtocolError::CompletelyBusted => None,
            ProtocolError::HeaderTooShort(id) => Some(id),
            ProtocolError::QuestionTooShort(id) => Some(id),
            ProtocolError::ResourceRecordTooShort(id) => Some(id),
            ProtocolError::DomainTooShort(id) => Some(id),
            ProtocolError::DomainTooLong(id) => Some(id),
            ProtocolError::DomainPointerInvalid(id) => Some(id),
            ProtocolError::DomainLabelInvalid(id) => Some(id),
        }
    }
}

/// A buffer which will be consumed by the parsing process.
pub struct ConsumableBuffer<'a> {
    octets: &'a [u8],
    position: usize,
}

impl<'a> ConsumableBuffer<'a> {
    pub fn new(octets: &'a [u8]) -> Self {
        Self {
            octets,
            position: 0,
        }
    }

    pub fn next_u8(&mut self) -> Option<u8> {
        if self.octets.len() > self.position {
            let a = self.octets[self.position];
            self.position += 1;
            Some(a)
        } else {
            None
        }
    }

    pub fn next_u16(&mut self) -> Option<u16> {
        if self.octets.len() > self.position + 1 {
            let a = self.octets[self.position];
            let b = self.octets[self.position + 1];
            self.position += 2;
            Some(u16::from_be_bytes([a, b]))
        } else {
            None
        }
    }

    pub fn next_u32(&mut self) -> Option<u32> {
        if self.octets.len() > self.position + 3 {
            let a = self.octets[self.position];
            let b = self.octets[self.position + 1];
            let c = self.octets[self.position + 2];
            let d = self.octets[self.position + 3];
            self.position += 4;
            Some(u32::from_be_bytes([a, b, c, d]))
        } else {
            None
        }
    }

    pub fn take(&mut self, size: usize) -> Option<&'a [u8]> {
        if self.octets.len() >= self.position + size {
            let slice = &self.octets[self.position..self.position + size];
            self.position += size;
            Some(slice)
        } else {
            None
        }
    }

    pub fn at_offset(&self, position: usize) -> ConsumableBuffer<'a> {
        Self {
            octets: self.octets,
            position,
        }
    }
}
