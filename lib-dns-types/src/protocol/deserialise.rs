//! Deserialisation of DNS messages from the network.  See the `types`
//! module for details of the format.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocol::types::*;

impl Message {
    /// # Errors
    ///
    /// If the message cannot be parsed.
    pub fn from_octets(octets: &[u8]) -> Result<Self, Error> {
        Self::deserialise(&mut ConsumableBuffer::new(octets))
    }

    /// # Errors
    ///
    /// If the message cannot be parsed.
    pub fn deserialise(buffer: &mut ConsumableBuffer) -> Result<Self, Error> {
        let wire_header = WireHeader::deserialise(buffer)?;
        let mut questions = Vec::with_capacity(wire_header.qdcount.into());
        let mut answers = Vec::with_capacity(wire_header.ancount.into());
        let mut authority = Vec::with_capacity(wire_header.nscount.into());
        let mut additional = Vec::with_capacity(wire_header.arcount.into());

        for _ in 0..wire_header.qdcount {
            questions.push(Question::deserialise(wire_header.header.id, buffer)?);
        }
        for _ in 0..wire_header.ancount {
            answers.push(ResourceRecord::deserialise(wire_header.header.id, buffer)?);
        }
        for _ in 0..wire_header.nscount {
            authority.push(ResourceRecord::deserialise(wire_header.header.id, buffer)?);
        }
        for _ in 0..wire_header.arcount {
            additional.push(ResourceRecord::deserialise(wire_header.header.id, buffer)?);
        }

        Ok(Self {
            header: wire_header.header,
            questions,
            answers,
            authority,
            additional,
        })
    }
}

impl WireHeader {
    /// # Errors
    ///
    /// If the header is too short.
    pub fn deserialise(buffer: &mut ConsumableBuffer) -> Result<Self, Error> {
        let id = buffer.next_u16().ok_or(Error::CompletelyBusted)?;
        let flags1 = buffer.next_u8().ok_or(Error::HeaderTooShort(id))?;
        let flags2 = buffer.next_u8().ok_or(Error::HeaderTooShort(id))?;
        let qdcount = buffer.next_u16().ok_or(Error::HeaderTooShort(id))?;
        let ancount = buffer.next_u16().ok_or(Error::HeaderTooShort(id))?;
        let nscount = buffer.next_u16().ok_or(Error::HeaderTooShort(id))?;
        let arcount = buffer.next_u16().ok_or(Error::HeaderTooShort(id))?;

        Ok(Self {
            header: Header {
                id,
                is_response: flags1 & HEADER_MASK_QR != 0,
                opcode: Opcode::from((flags1 & HEADER_MASK_OPCODE) >> HEADER_OFFSET_OPCODE),
                is_authoritative: flags1 & HEADER_MASK_AA != 0,
                is_truncated: flags1 & HEADER_MASK_TC != 0,
                recursion_desired: flags1 & HEADER_MASK_RD != 0,
                recursion_available: flags2 & HEADER_MASK_RA != 0,
                rcode: Rcode::from((flags2 & HEADER_MASK_RCODE) >> HEADER_OFFSET_RCODE),
            },
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }
}

impl Question {
    /// # Errors
    ///
    /// If the question cannot be parsed.
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, Error> {
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
    /// # Errors
    ///
    /// If the record cannot be parsed.
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, Error> {
        let name = DomainName::deserialise(id, buffer)?;
        let rtype = RecordType::deserialise(id, buffer)?;
        let rclass = RecordClass::deserialise(id, buffer)?;
        let ttl = buffer.next_u32().ok_or(Error::ResourceRecordTooShort(id))?;
        let rdlength = buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?;

        let rdata_start = buffer.position;

        let mut raw_rdata = || {
            if let Some(octets) = buffer.take(rdlength as usize) {
                Ok(octets.to_vec())
            } else {
                Err(Error::ResourceRecordTooShort(id))
            }
        };

        // for records which include domain names, deserialise them to
        // expand pointers.
        let rtype_with_data = match rtype {
            RecordType::A => RecordTypeWithData::A {
                address: Ipv4Addr::from(
                    buffer.next_u32().ok_or(Error::ResourceRecordTooShort(id))?,
                ),
            },
            RecordType::NS => RecordTypeWithData::NS {
                nsdname: DomainName::deserialise(id, buffer)?,
            },
            RecordType::MD => RecordTypeWithData::MD {
                madname: DomainName::deserialise(id, buffer)?,
            },
            RecordType::MF => RecordTypeWithData::MF {
                madname: DomainName::deserialise(id, buffer)?,
            },
            RecordType::CNAME => RecordTypeWithData::CNAME {
                cname: DomainName::deserialise(id, buffer)?,
            },
            RecordType::SOA => RecordTypeWithData::SOA {
                mname: DomainName::deserialise(id, buffer)?,
                rname: DomainName::deserialise(id, buffer)?,
                serial: buffer.next_u32().ok_or(Error::ResourceRecordTooShort(id))?,
                refresh: buffer.next_u32().ok_or(Error::ResourceRecordTooShort(id))?,
                retry: buffer.next_u32().ok_or(Error::ResourceRecordTooShort(id))?,
                expire: buffer.next_u32().ok_or(Error::ResourceRecordTooShort(id))?,
                minimum: buffer.next_u32().ok_or(Error::ResourceRecordTooShort(id))?,
            },
            RecordType::MB => RecordTypeWithData::MB {
                madname: DomainName::deserialise(id, buffer)?,
            },
            RecordType::MG => RecordTypeWithData::MG {
                mdmname: DomainName::deserialise(id, buffer)?,
            },
            RecordType::MR => RecordTypeWithData::MR {
                newname: DomainName::deserialise(id, buffer)?,
            },
            RecordType::NULL => RecordTypeWithData::NULL {
                octets: raw_rdata()?,
            },
            RecordType::WKS => RecordTypeWithData::WKS {
                octets: raw_rdata()?,
            },
            RecordType::PTR => RecordTypeWithData::PTR {
                ptrdname: DomainName::deserialise(id, buffer)?,
            },
            RecordType::HINFO => RecordTypeWithData::HINFO {
                octets: raw_rdata()?,
            },
            RecordType::MINFO => RecordTypeWithData::MINFO {
                rmailbx: DomainName::deserialise(id, buffer)?,
                emailbx: DomainName::deserialise(id, buffer)?,
            },
            RecordType::MX => RecordTypeWithData::MX {
                preference: buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                exchange: DomainName::deserialise(id, buffer)?,
            },
            RecordType::TXT => RecordTypeWithData::TXT {
                octets: raw_rdata()?,
            },
            RecordType::AAAA => RecordTypeWithData::AAAA {
                address: Ipv6Addr::new(
                    buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                    buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                    buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                    buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                    buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                    buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                    buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                    buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                ),
            },
            RecordType::SRV => RecordTypeWithData::SRV {
                priority: buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                weight: buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                port: buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?,
                target: DomainName::deserialise(id, buffer)?,
            },
            RecordType::Unknown(tag) => RecordTypeWithData::Unknown {
                tag,
                octets: raw_rdata()?,
            },
        };

        let rdata_stop = buffer.position;

        if rdata_stop == rdata_start + (rdlength as usize) {
            Ok(Self {
                name,
                rtype_with_data,
                rclass,
                ttl,
            })
        } else {
            Err(Error::ResourceRecordInvalid(id))
        }
    }
}

impl DomainName {
    /// # Errors
    ///
    /// If the domain cannot be parsed.
    #[allow(clippy::missing_panics_doc)]
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, Error> {
        let mut octets = Vec::<u8>::with_capacity(DOMAINNAME_MAX_LEN);
        let mut labels = Vec::<Label>::with_capacity(5);
        let start = buffer.position;

        'outer: loop {
            let size = buffer.next_u8().ok_or(Error::DomainTooShort(id))?;

            if usize::from(size) <= LABEL_MAX_LEN {
                octets.push(size);

                if size == 0 {
                    labels.push(Label::new());
                    break 'outer;
                }

                if let Some(os) = buffer.take(size as usize) {
                    // safe because of the bounds check above
                    let label = Label::try_from(os).unwrap();
                    for o in label.iter() {
                        octets.push(*o);
                    }
                    labels.push(label);
                } else {
                    return Err(Error::DomainTooShort(id));
                }

                if octets.len() > DOMAINNAME_MAX_LEN {
                    break 'outer;
                }
            } else if size >= 192 {
                // this requires re-parsing the pointed-to domain -
                // not great but works for now.
                let hi = size & 0b0011_1111;
                let lo = buffer.next_u8().ok_or(Error::DomainTooShort(id))?;
                let ptr = u16::from_be_bytes([hi, lo]).into();

                // pointer must be to an earlier record (not merely a
                // different one: an earlier one: RFC 1035 section
                // 4.1.4)
                if ptr >= start {
                    return Err(Error::DomainPointerInvalid(id));
                }

                let mut other = DomainName::deserialise(id, &mut buffer.at_offset(ptr))?;
                octets.append(&mut other.octets);
                labels.append(&mut other.labels);
                break 'outer;
            } else {
                return Err(Error::DomainLabelInvalid(id));
            }
        }

        if octets.len() <= DOMAINNAME_MAX_LEN {
            Ok(DomainName { octets, labels })
        } else {
            Err(Error::DomainTooLong(id))
        }
    }
}

impl QueryType {
    /// # Errors
    ///
    /// If the query type is too short.
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, Error> {
        let value = buffer.next_u16().ok_or(Error::QuestionTooShort(id))?;
        Ok(Self::from(value))
    }
}

impl QueryClass {
    /// # Errors
    ///
    /// If the query class is too short.
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, Error> {
        let value = buffer.next_u16().ok_or(Error::QuestionTooShort(id))?;
        Ok(Self::from(value))
    }
}

impl RecordType {
    /// # Errors
    ///
    /// If the record type is too short.
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, Error> {
        let value = buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?;
        Ok(Self::from(value))
    }
}

impl RecordClass {
    /// # Errors
    ///
    /// If the record class is too short.
    pub fn deserialise(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, Error> {
        let value = buffer.next_u16().ok_or(Error::ResourceRecordTooShort(id))?;
        Ok(Self::from(value))
    }
}

/// Errors encountered when parsing a datagram.  In all the errors
/// which have a `u16` parameter, that is the ID from the header - so
/// that an error response can be sent.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Error {
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

    /// A resource record is the wrong format.
    ResourceRecordInvalid(u16),

    /// A domain is incomplete.
    DomainTooShort(u16),

    /// A domain is over 255 octets in size.
    DomainTooLong(u16),

    /// A domain pointer points to or after the current record.
    DomainPointerInvalid(u16),

    /// A domain label is longer than 63 octets, but not a pointer.
    DomainLabelInvalid(u16),
}

impl Error {
    pub fn id(self) -> Option<u16> {
        match self {
            Error::CompletelyBusted => None,
            Error::HeaderTooShort(id) => Some(id),
            Error::QuestionTooShort(id) => Some(id),
            Error::ResourceRecordTooShort(id) => Some(id),
            Error::ResourceRecordInvalid(id) => Some(id),
            Error::DomainTooShort(id) => Some(id),
            Error::DomainTooLong(id) => Some(id),
            Error::DomainPointerInvalid(id) => Some(id),
            Error::DomainLabelInvalid(id) => Some(id),
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
