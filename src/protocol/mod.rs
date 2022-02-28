use std::slice;

/// Basic DNS message format, used for both queries and responses.
///
/// ```
///     +---------------------+
///     |        Header       |
///     +---------------------+
///     |       Question      | the question for the name server
///     +---------------------+
///     |        Answer       | RRs answering the question
///     +---------------------+
///     |      Authority      | RRs pointing toward an authority
///     +---------------------+
///     |      Additional     | RRs holding additional information
///     +---------------------+
/// ```
///
/// See section 4.1 of RFC 1035.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

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
}

/// Common header type for all messages.
///
/// ```
///                                     1  1  1  1  1  1
///       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      ID                       |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    QDCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ANCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    NSCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ARCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// See section 4.1.1 of RFC 1035.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Header {
    /// A 16 bit identifier assigned by the program that generates any
    /// kind of query.  This identifier is copied the corresponding
    /// reply and can be used by the requester to match up replies to
    /// outstanding queries.
    pub id: u16,

    /// A one bit field that specifies whether this message is a query
    /// (0), or a response (1).
    pub is_response: bool,

    /// A four bit field that specifies kind of query in this message.
    /// This value is set by the originator of a query and copied into
    /// the response.  The values are:
    ///
    /// - `0` a standard query (`QUERY`)
    ///
    /// - `1` an inverse query (`IQUERY`)
    ///
    /// - `2` a server status request (`STATUS`)
    ///
    /// - `3-15` reserved for future use
    pub opcode: Opcode,

    /// Authoritative Answer - this bit is valid in responses, and
    /// specifies that the responding name server is an authority for
    /// the domain name in question section.
    ///
    /// Note that the contents of the answer section may have multiple
    /// owner names because of aliases.  The AA bit corresponds to the
    /// name which matches the query name, or the first owner name in
    /// the answer section.
    pub is_authoritative: bool,

    /// TrunCation - specifies that this message was truncated due to
    /// length greater than that permitted on the transmission
    /// channel.
    pub is_truncated: bool,

    /// Recursion Desired - this bit may be set in a query and is
    /// copied into the response.  If RD is set, it directs the name
    /// server to pursue the query recursively.  Recursive query
    /// support is optional.
    pub recursion_desired: bool,

    /// Recursion Available - this be is set or cleared in a response,
    /// and denotes whether recursive query support is available in
    /// the name server.
    pub recursion_available: bool,

    /// Response code - this 4 bit field is set as part of responses.
    /// The values have the following interpretation:
    ///
    /// - `0` No error condition
    ///
    /// - `1` Format error - The name server was unable to interpret
    ///       the query.
    ///
    /// - `2` Server failure - The name server was unable to process
    ///       this query due to a problem with the name server.
    ///
    /// - `3` Name Error - Meaningful only for responses from an
    ///       authoritative name server, this code signifies that the
    ///       domain name referenced in the query does not exist.
    ///
    /// - `4` Not Implemented - The name server does not support the
    ///       requested kind of query.
    ///
    /// - `5` Refused - The name server refuses to perform the
    ///       specified operation for policy reasons.  For example, a
    ///       name server may not wish to provide the information to
    ///       the particular requester, or a name server may not wish
    ///       to perform a particular operation (e.g., zone transfer)
    ///       for particular data.
    ///
    /// - `6-15` Reserved for future use.
    pub rcode: Rcode,

    /// an unsigned 16 bit integer specifying the number of entries in
    /// the question section.
    pub qdcount: u16,

    /// an unsigned 16 bit integer specifying the number of resource
    /// records in the answer section.
    pub ancount: u16,

    /// an unsigned 16 bit integer specifying the number of name
    /// server resource records in the authority records section.
    pub nscount: u16,

    /// an unsigned 16 bit integer specifying the number of
    /// resource records in the additional records section.
    pub arcount: u16,
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
            opcode: Opcode::from_u8((flags1 & 0b01111000) >> 3),
            is_authoritative: flags1 & 0b00000100 != 0,
            is_truncated: flags1 & 0b00000010 != 0,
            recursion_desired: flags1 & 0b00000001 != 0,
            recursion_available: flags2 & 0b10000000 != 0,
            rcode: Rcode::from_u8(flags2 & 0b00001111),
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        let flags1 = (if self.is_response { 0b10000000 } else { 0 })
            | (0b01111000 & (self.opcode.to_u8() << 3))
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
        }) | (0b00001111 & self.rcode.to_u8());

        buffer.write_u16(self.id);
        buffer.write_u8(flags1);
        buffer.write_u8(flags2);
        buffer.write_u16(self.qdcount);
        buffer.write_u16(self.ancount);
        buffer.write_u16(self.nscount);
        buffer.write_u16(self.arcount);
    }
}

/// The question section has a list of questions (usually 1 but
/// possibly more) being asked.  This is the structure for a single
/// question.
///
/// ```
///                                     1  1  1  1  1  1
///       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                                               |
///     /                     QNAME                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     QTYPE                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     QCLASS                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// See section 4.1.2 of RFC 1035.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Question {
    /// a domain name represented as a sequence of labels, where each
    /// label consists of a length octet followed by that number of
    /// octets.  The domain name terminates with the zero length octet
    /// for the null label of the root.  Note that this field may be
    /// an odd number of octets; no padding is used.
    pub name: DomainName,

    /// a two octet code which specifies the type of the query.  The
    /// values for this field include all codes valid for a TYPE
    /// field, together with some more general codes which can match
    /// more than one type of RR.
    pub qtype: QueryType,

    /// a two octet code that specifies the class of the query.  For
    /// example, the QCLASS field is IN for the Internet.
    pub qclass: QueryClass,
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

/// The answer, authority, and additional sections are all the same
/// format: a variable number of resource records.  This is the
/// structure for a single resource record.
///
/// ```
///                                     1  1  1  1  1  1
///       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                                               |
///     /                                               /
///     /                      NAME                     /
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TYPE                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     CLASS                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TTL                      |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                   RDLENGTH                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
///     /                     RDATA                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// See section 4.1.3 of RFC 1035.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResourceRecord {
    /// a domain name to which this resource record pertains.
    pub name: DomainName,

    /// A combination of the RTYPE and RDATA fields
    pub rtype_with_data: RecordTypeWithData,

    /// two octets which specify the class of the data in the RDATA
    /// field.
    pub rclass: RecordClass,

    /// a 32 bit unsigned integer that specifies the time interval (in
    /// seconds) that the resource record may be cached before it
    /// should be discarded.  Zero values are interpreted to mean that
    /// the RR can only be used for the transaction in progress, and
    /// should not be cached.
    pub ttl: u32,
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
                let mut octets = Vec::with_capacity(rdlength.into());
                for _ in 0..rdlength {
                    let octet = buffer
                        .next_u8()
                        .ok_or(ProtocolError::ResourceRecordTooShort(id))?;
                    octets.push(octet);
                }
                RecordTypeWithData::Uninterpreted { rtype, octets }
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

/// A record type with its associated data.  This is so any pointers
/// in domain names will be expanded before further processing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RecordTypeWithData {
    Uninterpreted {
        rtype: RecordType,
        octets: Vec<u8>,
    },
    Named {
        rtype: RecordType,
        name: DomainName,
    },
    MINFO {
        rmailbx: DomainName,
        emailbx: DomainName,
    },
    MX {
        preference: u16,
        exchange: DomainName,
    },
    SOA {
        mname: DomainName,
        rname: DomainName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
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

/// What sort of query this is.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Opcode {
    Standard,
    Inverse,
    Status,
    Reserved(u8),
}

impl Opcode {
    pub fn from_u8(octet: u8) -> Opcode {
        match octet {
            0 => Opcode::Standard,
            1 => Opcode::Inverse,
            2 => Opcode::Status,
            _ => Opcode::Reserved(octet),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Opcode::Standard => 0,
            Opcode::Inverse => 1,
            Opcode::Status => 2,
            Opcode::Reserved(octet) => octet,
        }
    }
}

/// What sort of response this is.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved(u8),
}

impl Rcode {
    pub fn from_u8(octet: u8) -> Rcode {
        match octet {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            _ => Rcode::Reserved(octet),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Rcode::NoError => 0,
            Rcode::FormatError => 1,
            Rcode::ServerFailure => 2,
            Rcode::NameError => 3,
            Rcode::NotImplemented => 4,
            Rcode::Refused => 5,
            Rcode::Reserved(octet) => octet,
        }
    }
}

/// A domain name is a sequence of labels, where each label is a
/// length octet followed by that number of octets.  Since there is no
/// particular character encoding needed, and this application does
/// not need to inspect domain names, they are left in this opaque
/// format.
///
/// A label must be 63 octets or shorter.  A name must be 255 octets
/// or shorter in total, including both length and label octets.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct DomainName {
    pub octets: Vec<u8>,
    pub labels: Vec<Vec<u8>>,
}

impl DomainName {
    pub fn root_domain() -> Self {
        DomainName {
            octets: vec![0],
            labels: vec![vec![]],
        }
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

                for _ in 0..size {
                    let octet = buffer
                        .next_u8()
                        .ok_or(ProtocolError::DomainTooShort(id))?
                        .to_ascii_lowercase();
                    octets.push(octet);
                    label.push(octet);

                    if octets.len() > 255 {
                        labels.push(label);
                        break 'outer;
                    }
                }
                labels.push(label);
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

/// Query types are a superset of record types.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum QueryType {
    Record(RecordType),
    AXFR,
    MAILB,
    MAILA,
    Wildcard,
}

impl QueryType {
    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::QuestionTooShort(id))?;
        Ok(Self::from_u16(value))
    }

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.to_u16());
    }

    pub fn from_u16(value: u16) -> Self {
        match value {
            252 => QueryType::AXFR,
            253 => QueryType::MAILB,
            254 => QueryType::MAILA,
            255 => QueryType::Wildcard,
            _ => QueryType::Record(RecordType::from_u16(value)),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            QueryType::AXFR => 252,
            QueryType::MAILB => 253,
            QueryType::MAILA => 254,
            QueryType::Wildcard => 255,
            QueryType::Record(rtype) => rtype.to_u16(),
        }
    }
}

/// Query classes are a superset of record classes.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum QueryClass {
    Record(RecordClass),
    Wildcard,
}

impl QueryClass {
    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::QuestionTooShort(id))?;
        Ok(Self::from_u16(value))
    }

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.to_u16());
    }

    pub fn from_u16(value: u16) -> Self {
        match value {
            255 => QueryClass::Wildcard,
            _ => QueryClass::Record(RecordClass::from_u16(value)),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            QueryClass::Wildcard => 255,
            QueryClass::Record(rclass) => rclass.to_u16(),
        }
    }
}

/// Record types are used by resource records and by queries.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RecordType {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    Unknown(u16),
}

impl RecordType {
    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::ResourceRecordTooShort(id))?;
        Ok(Self::from_u16(value))
    }

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.to_u16());
    }

    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            3 => RecordType::MD,
            4 => RecordType::MF,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            7 => RecordType::MB,
            8 => RecordType::MG,
            9 => RecordType::MR,
            10 => RecordType::NULL,
            11 => RecordType::WKS,
            12 => RecordType::PTR,
            13 => RecordType::HINFO,
            14 => RecordType::MINFO,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            _ => RecordType::Unknown(value),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::MD => 3,
            RecordType::MF => 4,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::MB => 7,
            RecordType::MG => 8,
            RecordType::MR => 9,
            RecordType::NULL => 10,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MINFO => 14,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::Unknown(value) => value,
        }
    }

    pub fn matches(&self, qtype: &QueryType) -> bool {
        match qtype {
            QueryType::Wildcard => true,
            QueryType::Record(rtype) => rtype == self,
            _ => false,
        }
    }
}

/// Record classes are used by resource records and by queries.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RecordClass {
    IN,
    CS,
    CH,
    HS,
    Unknown(u16),
}

impl RecordClass {
    pub fn parse(id: u16, buffer: &mut ConsumableBuffer) -> Result<Self, ProtocolError> {
        let value = buffer
            .next_u16()
            .ok_or(ProtocolError::ResourceRecordTooShort(id))?;
        Ok(Self::from_u16(value))
    }

    pub fn serialise(self, buffer: &mut WritableBuffer) {
        buffer.write_u16(self.to_u16());
    }

    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordClass::IN,
            2 => RecordClass::CS,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            _ => RecordClass::Unknown(value),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordClass::IN => 1,
            RecordClass::CS => 2,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::Unknown(value) => value,
        }
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
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
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
    iter: slice::Iter<'a, u8>,
    octets: &'a [u8],
    position: usize,
}

impl<'a> ConsumableBuffer<'a> {
    pub fn new(octets: &'a [u8]) -> Self {
        Self {
            iter: octets.iter(),
            octets,
            position: 0,
        }
    }

    pub fn next_u8(&mut self) -> Option<u8> {
        let octet = self.iter.next().copied();

        if octet.is_some() {
            self.position += 1;
        }

        octet
    }

    pub fn next_u16(&mut self) -> Option<u16> {
        if let Some(hi) = self.next_u8() {
            if let Some(lo) = self.next_u8() {
                return Some(u16::from_be_bytes([hi, lo]));
            }
        }
        None
    }

    pub fn next_u32(&mut self) -> Option<u32> {
        if let Some(hihi) = self.next_u8() {
            if let Some(lohi) = self.next_u8() {
                if let Some(hilo) = self.next_u8() {
                    if let Some(lolo) = self.next_u8() {
                        return Some(u32::from_be_bytes([hihi, lohi, hilo, lolo]));
                    }
                }
            }
        }
        None
    }

    pub fn at_offset(&self, position: usize) -> ConsumableBuffer<'a> {
        let mut iter = self.octets.iter();
        if position > 0 {
            iter.nth(position - 1);
        }

        Self {
            iter,
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
