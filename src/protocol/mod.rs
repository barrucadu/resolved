pub mod wire_types;

use self::wire_types::*;

impl Message {
    pub fn parse(buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let header = Header::parse(buffer)?;
        let mut questions = Vec::with_capacity(header.qdcount.into());
        let mut answers = Vec::with_capacity(header.ancount.into());
        let mut authority = Vec::with_capacity(header.nscount.into());
        let mut additional = Vec::with_capacity(header.arcount.into());

        for _ in 0..header.qdcount {
            questions.push(Question::parse(header.id, buffer)?);
        }
        for _ in 0..header.ancount {
            answers.push(ResourceRecord::parse(header.id, buffer)?);
        }
        for _ in 0..header.nscount {
            authority.push(ResourceRecord::parse(header.id, buffer)?);
        }
        for _ in 0..header.arcount {
            additional.push(ResourceRecord::parse(header.id, buffer)?);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }

    pub fn serialise_for_udp(self) -> Vec<u8> {
        let mut serialised = self.serialise();

        if serialised.len() > 512 {
            // set TC flag and shrink to fit
            serialised[3] |= 0b00000010;
            serialised.resize(512, 0);
        }

        serialised
    }

    /// Like `serialise_for_udp` but returns `None` instead of
    /// truncating.
    pub fn serialise_for_udp_if_not_too_big(self) -> Option<Vec<u8>> {
        let serialised = self.serialise();
        if serialised.len() > 512 {
            None
        } else {
            Some(serialised)
        }
    }

    pub fn serialise_for_tcp(self) -> Vec<u8> {
        let mut serialised = self.serialise();
        let mut serialised_with_length = Vec::with_capacity(2 + serialised.len());

        let len: u16 = serialised.len().try_into().unwrap();
        let [hi, lo] = len.to_be_bytes();
        serialised_with_length.push(hi);
        serialised_with_length.push(lo);
        serialised_with_length.append(&mut serialised);

        serialised_with_length
    }

    pub fn serialise(self) -> Vec<u8> {
        let mut buffer = WritableBuffer::default();

        self.header.serialise(&mut buffer);
        for question in self.questions {
            question.serialise(&mut buffer);
        }
        for rr in self.answers {
            rr.serialise(&mut buffer);
        }
        for rr in self.authority {
            rr.serialise(&mut buffer);
        }
        for rr in self.additional {
            rr.serialise(&mut buffer);
        }

        buffer.octets
    }

    pub fn make_response(&self) -> Self {
        Self {
            header: Header {
                id: self.header.id,
                is_response: true,
                opcode: self.header.opcode,
                is_authoritative: false,
                is_truncated: false,
                recursion_desired: self.header.recursion_desired,
                recursion_available: false,
                rcode: Rcode::NoError,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn make_format_error_response(id: u16) -> Self {
        Self {
            header: Header {
                id,
                is_response: true,
                opcode: Opcode::Standard,
                is_authoritative: false,
                is_truncated: false,
                recursion_desired: false,
                recursion_available: false,
                rcode: Rcode::FormatError,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn from_question(id: u16, question: Question) -> Self {
        Self {
            header: Header {
                id,
                is_response: false,
                opcode: Opcode::Standard,
                is_authoritative: false,
                is_truncated: false,
                recursion_desired: false,
                recursion_available: false,
                rcode: Rcode::NoError,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![question],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }
}

impl Header {
    pub fn parse(buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
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

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        let flags1 = (if self.is_response { 0b10000000 } else { 0 })
            | (0b01111000 & (u8::from(self.opcode) << 3))
            | (if self.is_authoritative { 0b00000100 } else { 0 })
            | (if self.is_truncated { 0b00000010 } else { 0 })
            | (if self.recursion_desired {
                0b00000001
            } else {
                0
            });
        let flags2 = (if self.recursion_available {
            0b1000000
        } else {
            0
        }) | (0b00001111 & u8::from(self.rcode));

        buffer.write_u16(self.id);
        buffer.write_u8(flags1);
        buffer.write_u8(flags2);
        buffer.write_u16(self.qdcount);
        buffer.write_u16(self.ancount);
        buffer.write_u16(self.nscount);
        buffer.write_u16(self.arcount);
    }
}

impl Question {
    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let name = DomainName::parse(id, buffer)?;
        let qtype = QueryType::parse(id, buffer)?;
        let qclass = QueryClass::parse(id, buffer)?;

        Ok(Self {
            name,
            qtype,
            qclass,
        })
    }

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        self.name.serialise(buffer);
        self.qtype.serialise(buffer);
        self.qclass.serialise(buffer);
    }
}

impl ResourceRecord {
    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let name = DomainName::parse(id, buffer)?;
        let rtype = RecordType::parse(id, buffer)?;
        let rclass = RecordClass::parse(id, buffer)?;
        let ttl = buffer
            .next_u32()
            .ok_or(ProtocolError::ResourceRecordTooShort(id))?;
        let rdlength = buffer
            .next_u16()
            .ok_or(ProtocolError::ResourceRecordTooShort(id))?;

        // for records which include domain names, parse them to
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
                name: DomainName::parse(id, buffer)?,
            },

            RecordType::MINFO => RecordTypeWithData::MINFO {
                rmailbx: DomainName::parse(id, buffer)?,
                emailbx: DomainName::parse(id, buffer)?,
            },

            RecordType::MX => RecordTypeWithData::MX {
                preference: buffer
                    .next_u16()
                    .ok_or(ProtocolError::ResourceRecordTooShort(id))?,
                exchange: DomainName::parse(id, buffer)?,
            },

            RecordType::SOA => RecordTypeWithData::SOA {
                mname: DomainName::parse(id, buffer)?,
                rname: DomainName::parse(id, buffer)?,
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

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        let (rtype, rdata) = match self.rtype_with_data {
            RecordTypeWithData::Uninterpreted { rtype, octets } => (rtype, octets),
            RecordTypeWithData::Named { rtype, name } => (rtype, name.octets),
            RecordTypeWithData::MINFO { rmailbx, emailbx } => {
                let mut octets = Vec::with_capacity(rmailbx.octets.len() + emailbx.octets.len());
                for octet in rmailbx.octets {
                    octets.push(octet)
                }
                for octet in emailbx.octets {
                    octets.push(octet)
                }
                (RecordType::MINFO, octets)
            }
            RecordTypeWithData::MX {
                preference,
                exchange,
            } => {
                let mut octets = Vec::with_capacity(2 + exchange.octets.len());
                for octet in preference.to_be_bytes() {
                    octets.push(octet)
                }
                for octet in exchange.octets {
                    octets.push(octet)
                }
                (RecordType::MX, octets)
            }
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
                    octets.push(octet)
                }
                for octet in rname.octets {
                    octets.push(octet)
                }
                for octet in serial.to_be_bytes() {
                    octets.push(octet)
                }
                for octet in refresh.to_be_bytes() {
                    octets.push(octet)
                }
                for octet in retry.to_be_bytes() {
                    octets.push(octet)
                }
                for octet in expire.to_be_bytes() {
                    octets.push(octet)
                }
                for octet in minimum.to_be_bytes() {
                    octets.push(octet)
                }
                (RecordType::SOA, octets)
            }
        };

        self.name.serialise(buffer);
        rtype.serialise(buffer);
        self.rclass.serialise(buffer);
        buffer.write_u32(self.ttl);
        // TODO: remove use of unwrap
        buffer.write_u16(rdata.len().try_into().unwrap());
        buffer.write_octets(rdata);
    }
}

impl RecordTypeWithData {
    pub fn rtype(&self) -> RecordType {
        match self {
            RecordTypeWithData::Uninterpreted { rtype, octets: _ } => *rtype,
            RecordTypeWithData::Named { rtype, name: _ } => *rtype,
            RecordTypeWithData::MINFO {
                rmailbx: _,
                emailbx: _,
            } => RecordType::MINFO,
            RecordTypeWithData::MX {
                preference: _,
                exchange: _,
            } => RecordType::MX,
            RecordTypeWithData::SOA {
                mname: _,
                rname: _,
                serial: _,
                refresh: _,
                retry: _,
                expire: _,
                minimum: _,
            } => RecordType::SOA,
        }
    }

    pub fn matches(&self, qtype: &QueryType) -> bool {
        self.rtype().matches(qtype)
    }
}

impl DomainName {
    pub fn root_domain() -> Self {
        DomainName {
            octets: vec![0],
            labels: vec![vec![]],
        }
    }

    pub fn to_dotted_string(&self) -> String {
        let mut out = String::with_capacity(self.octets.len());
        for label in &self.labels {
            for octet in label {
                out.push(*octet as char);
            }
            if !label.is_empty() {
                out.push('.');
            }
        }
        out
    }

    pub fn from_dotted_string(s: &str) -> Option<Self> {
        let mut labels = Vec::<Vec<u8>>::with_capacity(5);
        let mut blank_label = false;

        for label in s.split('.') {
            if blank_label {
                return None;
            }

            let label = label.as_bytes();
            blank_label = label.is_empty();
            labels.push(label.into());
        }

        if !blank_label {
            labels.push(Vec::new());
        }

        Self::from_labels(labels)
    }

    pub fn from_labels(mixed_case_labels: Vec<Vec<u8>>) -> Option<Self> {
        let mut labels = Vec::<Vec<u8>>::with_capacity(mixed_case_labels.len());
        let mut octets = Vec::<u8>::with_capacity(255);
        let mut blank_label = false;

        for mc_label in &mixed_case_labels {
            if blank_label {
                return None;
            }

            blank_label = mc_label.is_empty();

            match mc_label.len().try_into() {
                Ok(n) if n <= 63 => {
                    octets.push(n);
                    let mut label = Vec::<u8>::with_capacity(mc_label.len());
                    for octet in mc_label {
                        let octet = octet.to_ascii_lowercase();
                        label.push(octet);
                        octets.push(octet);
                    }
                    labels.push(label);
                }
                _ => return None,
            }
        }

        if blank_label && octets.len() <= 255 {
            Some(Self { octets, labels })
        } else {
            None
        }
    }

    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
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

                let mut other = DomainName::parse(id, &mut buffer.at_offset(ptr))?;
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

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        // TODO: implement compression - this'll need some extra state
        // in the WritableBuffer to keep track of previously-written
        // domains and labels.
        buffer.write_octets(self.octets);
    }

    pub fn is_subdomain_of(&self, other: &DomainName) -> bool {
        self.labels.ends_with(&other.labels)
    }
}

impl QueryType {
    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::QuestionTooShort(id))?;
        Ok(Self::from(value))
    }

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.into());
    }
}

impl QueryClass {
    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::QuestionTooShort(id))?;
        Ok(Self::from(value))
    }

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.into());
    }
}

impl RecordType {
    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::ResourceRecordTooShort(id))?;
        Ok(Self::from(value))
    }

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.into());
    }

    pub fn matches(&self, qtype: &QueryType) -> bool {
        match qtype {
            QueryType::Wildcard => true,
            QueryType::Record(rtype) => rtype == self,
            _ => false,
        }
    }
}

impl RecordClass {
    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::ResourceRecordTooShort(id))?;
        Ok(Self::from(value))
    }

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.into());
    }

    pub fn matches(&self, qclass: &QueryClass) -> bool {
        match qclass {
            QueryClass::Wildcard => true,
            QueryClass::Record(rclass) => rclass == self,
        }
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

/// A buffer which can be written to, for serialisation purposes.
pub struct WritableBuffer {
    octets: Vec<u8>,
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
