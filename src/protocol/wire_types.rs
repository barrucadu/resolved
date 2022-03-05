/// Basic DNS message format, used for both queries and responses.
///
/// ```text
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
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

/// Common header type for all messages.
///
/// ```text
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
}

/// A `Header` as it appears on the network.  This type is used for
/// serialisation and deserialisation only: including the count fields
/// in the normal `Header` type would require ensuring those values
/// are correct.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct WireHeader {
    /// The header that will be persisted to / is taken from the
    /// `Message`.
    pub header: Header,

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

/// The question section has a list of questions (usually 1 but
/// possibly more) being asked.  This is the structure for a single
/// question.
///
/// ```text
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
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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

/// The answer, authority, and additional sections are all the same
/// format: a variable number of resource records.  This is the
/// structure for a single resource record.
///
/// ```text
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
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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

/// A record type with its associated, deserialised, data.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RecordTypeWithData {
    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    ADDRESS                    |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `ADDRESS` is a 32 bit Internet address.
    A { octets: Vec<u8> },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   NSDNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `NSDNAME` is a domain name which specifies a host which
    /// should be authoritative for the specified class and domain.
    NS { nsdname: DomainName },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   MADNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `MADNAME` is a domain name which specifies a host which
    /// has a mail agent for the domain which should be able to
    /// deliver mail for the domain.
    MD { madname: DomainName },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   MADNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `MADNAME` is a domain name which specifies a host which
    /// has a mail agent for the domain which will accept mail for
    /// forwarding to the domain.
    MF { madname: DomainName },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                     CNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `CNAME` is a domain name which specifies the canonical
    /// or primary name for the owner.  The owner name is an alias.
    CNAME { cname: DomainName },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                     MNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                     RNAME                     /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    SERIAL                     |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    REFRESH                    |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                     RETRY                     |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    EXPIRE                     |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    MINIMUM                    |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `MNAME` is the domain name of the name server that was
    /// the original or primary source of data for this zone.
    ///
    /// Where `RNAME` is a domain name which specifies the mailbox of
    /// the person responsible for this zone.
    ///
    /// Where `SERIAL` is the unsigned 32 bit version number of the
    /// original copy of the zone.  Zone transfers preserve this
    /// value.  This value wraps and should be compared using sequence
    /// space arithmetic.
    ///
    /// Where `REFRESH` is a 32 bit time interval before the zone
    /// should be refreshed.
    ///
    /// Where `RETRY` is a 32 bit time interval that should elapse
    /// before a failed refresh should be retried.
    ///
    /// Where `EXPIRE` is a 32 bit time value that specifies an upper
    /// limit on the time interval that can elapse before the zone is
    /// no longer authoritative.
    ///
    /// Where `MINIMUM` is the unsigned 32 bit minimum TTL field that
    /// should be exported with any RR from this zone.
    ///
    /// All times are in units of seconds.
    SOA {
        mname: DomainName,
        rname: DomainName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   MADNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `MADNAME` is a domain name which specifies a host which
    /// has the specified mailbox.
    MB { madname: DomainName },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   MGMNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `MGMNAME` is a domain name which specifies a mailbox
    /// which is a member of the mail group specified by the domain
    /// name.
    MG { mdmname: DomainName },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   NEWNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `NEWNAME` is a domain name which specifies a mailbox
    /// which is the proper rename of the specifies mailbox.
    MR { newname: DomainName },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                  <anything>                   /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Anything at all may be in the RDATA field so long as it is
    /// 65535 octets or less.
    NULL { octets: Vec<u8> },

    /// This application does not interpret `WKS` records.
    WKS { octets: Vec<u8> },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   PTRDNAME                    /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `PTRDNAME` is a domain name which points to some
    /// location in the domain name space.
    PTR { ptrdname: DomainName },

    /// This application does not interpret `HINFO` records.
    HINFO { octets: Vec<u8> },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                    RMAILBX                    /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                    EMAILBX                    /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `RMAILBX` is a domain name which specifies a mailbox
    /// which is responsible for the mailing list or mailbox.  If this
    /// domain name names the root, the owner of the `MINFO` RR is
    /// responsible for itself.
    ///
    /// Where `EMAILBX` is a domain name which specifies a mailbox
    /// which is to receive error messages related to the mailing list
    /// or mailbox specified by the owner of the `MINFO` RR (similar
    /// to the `ERRORS-TO`: field which has been proposed).  If this
    /// domain name names the root, errors should be returned to the
    /// sender of the message.
    MINFO {
        rmailbx: DomainName,
        emailbx: DomainName,
    },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                  PREFERENCE                   |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   EXCHANGE                    /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `PREFERENCE` is a 16 bit integer which specifies the
    /// preference given to this RR among others at the same owner.
    /// Lower values are preferred.
    ///
    /// Where `EXCHANGE` is a domain name which specifies a host
    /// willing to act as a mail exchange for the owner name.
    MX {
        preference: u16,
        exchange: DomainName,
    },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   TXT-DATA                    /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `TXT-DATA` is one or more character strings.
    TXT { octets: Vec<u8> },

    /// Any other record.
    Unknown {
        tag: RecordTypeUnknown,
        octets: Vec<u8>,
    },
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for RecordTypeWithData {
    // this is pretty verbose but it feels like a better way to
    // guarantee the max size of the `Vec<u8>`s than adding a wrapper
    // type
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0..=128)?;
        let octets = Vec::from(u.bytes(len)?);

        let rtype_with_data = match u.arbitrary::<RecordType>()? {
            RecordType::A => RecordTypeWithData::A { octets },
            RecordType::NS => RecordTypeWithData::NS {
                nsdname: u.arbitrary()?,
            },
            RecordType::MD => RecordTypeWithData::MD {
                madname: u.arbitrary()?,
            },
            RecordType::MF => RecordTypeWithData::MF {
                madname: u.arbitrary()?,
            },
            RecordType::CNAME => RecordTypeWithData::CNAME {
                cname: u.arbitrary()?,
            },
            RecordType::SOA => RecordTypeWithData::SOA {
                mname: u.arbitrary()?,
                rname: u.arbitrary()?,
                serial: u.arbitrary()?,
                refresh: u.arbitrary()?,
                retry: u.arbitrary()?,
                expire: u.arbitrary()?,
                minimum: u.arbitrary()?,
            },
            RecordType::MB => RecordTypeWithData::MB {
                madname: u.arbitrary()?,
            },
            RecordType::MG => RecordTypeWithData::MG {
                mdmname: u.arbitrary()?,
            },
            RecordType::MR => RecordTypeWithData::MR {
                newname: u.arbitrary()?,
            },
            RecordType::NULL => RecordTypeWithData::NULL { octets },
            RecordType::WKS => RecordTypeWithData::WKS { octets },
            RecordType::PTR => RecordTypeWithData::PTR {
                ptrdname: u.arbitrary()?,
            },
            RecordType::HINFO => RecordTypeWithData::HINFO { octets },
            RecordType::MINFO => RecordTypeWithData::MINFO {
                rmailbx: u.arbitrary()?,
                emailbx: u.arbitrary()?,
            },
            RecordType::MX => RecordTypeWithData::MX {
                preference: u.arbitrary()?,
                exchange: u.arbitrary()?,
            },
            RecordType::TXT => RecordTypeWithData::TXT { octets },
            RecordType::Unknown(tag) => RecordTypeWithData::Unknown { tag, octets },
        };
        Ok(rtype_with_data)
    }
}

/// What sort of query this is.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Opcode {
    Standard,
    Inverse,
    Status,
    Reserved(OpcodeReserved),
}

/// A struct with a private constructor, to ensure invalid `Opcode`s
/// cannot be created.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OpcodeReserved(u8);

impl From<u8> for Opcode {
    fn from(octet: u8) -> Self {
        match octet & 0b00001111 {
            0 => Opcode::Standard,
            1 => Opcode::Inverse,
            2 => Opcode::Status,
            other => Opcode::Reserved(OpcodeReserved(other)),
        }
    }
}

impl From<Opcode> for u8 {
    fn from(value: Opcode) -> Self {
        match value {
            Opcode::Standard => 0,
            Opcode::Inverse => 1,
            Opcode::Status => 2,
            Opcode::Reserved(OpcodeReserved(octet)) => octet,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Opcode {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u8>()?))
    }
}

/// What sort of response this is.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved(RcodeReserved),
}

/// A struct with a private constructor, to ensure invalid `Rcode`s
/// cannot be created.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RcodeReserved(u8);

impl From<u8> for Rcode {
    fn from(octet: u8) -> Self {
        match octet & 0b00001111 {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            other => Rcode::Reserved(RcodeReserved(other)),
        }
    }
}

impl From<Rcode> for u8 {
    fn from(value: Rcode) -> Self {
        match value {
            Rcode::NoError => 0,
            Rcode::FormatError => 1,
            Rcode::ServerFailure => 2,
            Rcode::NameError => 3,
            Rcode::NotImplemented => 4,
            Rcode::Refused => 5,
            Rcode::Reserved(RcodeReserved(octet)) => octet,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Rcode {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u8>()?))
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
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DomainName {
    pub octets: Vec<u8>,
    pub labels: Vec<Vec<u8>>,
}

impl std::fmt::Debug for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainName")
            .field("to_dotted_string()", &self.to_dotted_string())
            .finish()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for DomainName {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_labels = u.int_in_range::<usize>(0..=10)?;
        let mut octets = Vec::new();
        let mut labels = Vec::new();
        for _ in 0..num_labels {
            let label_len = u.int_in_range::<u8>(1..=20)?;
            let mut label = Vec::new();
            octets.push(label_len);
            let os = u.bytes(label_len.into())?;
            for o in os {
                label.push(o.to_ascii_lowercase());
                octets.push(o.to_ascii_lowercase());
            }
            labels.push(label);
        }
        octets.push(0);
        labels.push(Vec::new());
        Ok(Self { octets, labels })
    }
}

/// Query types are a superset of record types.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum QueryType {
    Record(RecordType),
    AXFR,
    MAILB,
    MAILA,
    Wildcard,
}

impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            252 => QueryType::AXFR,
            253 => QueryType::MAILB,
            254 => QueryType::MAILA,
            255 => QueryType::Wildcard,
            _ => QueryType::Record(RecordType::from(value)),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(value: QueryType) -> Self {
        match value {
            QueryType::AXFR => 252,
            QueryType::MAILB => 253,
            QueryType::MAILA => 254,
            QueryType::Wildcard => 255,
            QueryType::Record(rtype) => rtype.into(),
        }
    }
}
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for QueryType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u16>()?))
    }
}

/// Query classes are a superset of record classes.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum QueryClass {
    Record(RecordClass),
    Wildcard,
}

impl From<u16> for QueryClass {
    fn from(value: u16) -> Self {
        match value {
            255 => QueryClass::Wildcard,
            _ => QueryClass::Record(RecordClass::from(value)),
        }
    }
}

impl From<QueryClass> for u16 {
    fn from(value: QueryClass) -> Self {
        match value {
            QueryClass::Wildcard => 255,
            QueryClass::Record(rclass) => rclass.into(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for QueryClass {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u16>()?))
    }
}

/// Record types are used by resource records and by queries.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
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
    Unknown(RecordTypeUnknown),
}

/// A struct with a private constructor, to ensure invalid `RecordType`s
/// cannot be created.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RecordTypeUnknown(u16);

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
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
            _ => RecordType::Unknown(RecordTypeUnknown(value)),
        }
    }
}

impl From<RecordType> for u16 {
    fn from(value: RecordType) -> Self {
        match value {
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
            RecordType::Unknown(RecordTypeUnknown(value)) => value,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for RecordType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u16>()?))
    }
}

/// Record classes are used by resource records and by queries.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RecordClass {
    IN,
    CS,
    CH,
    HS,
    Unknown(RecordClassUnknown),
}

/// A struct with a private constructor, to ensure invalid
/// `RecordClass`es cannot be created.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RecordClassUnknown(u16);

impl From<u16> for RecordClass {
    fn from(value: u16) -> Self {
        match value {
            1 => RecordClass::IN,
            2 => RecordClass::CS,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            _ => RecordClass::Unknown(RecordClassUnknown(value)),
        }
    }
}

impl From<RecordClass> for u16 {
    fn from(value: RecordClass) -> Self {
        match value {
            RecordClass::IN => 1,
            RecordClass::CS => 2,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::Unknown(RecordClassUnknown(value)) => value,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for RecordClass {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u16>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u8_opcode_roundtrip() {
        for i in 0..15 {
            assert_eq!(u8::from(Opcode::from(i)), i);
        }
    }

    #[test]
    fn u8_rcode_roundtrip() {
        for i in 0..15 {
            assert_eq!(u8::from(Rcode::from(i)), i);
        }
    }

    #[test]
    fn u16_querytype_roundtrip() {
        for i in 0..100 {
            assert_eq!(u16::from(QueryType::from(i)), i);
        }
    }

    #[test]
    fn u16_queryclass_roundtrip() {
        for i in 0..100 {
            assert_eq!(u16::from(QueryClass::from(i)), i);
        }
    }

    #[test]
    fn u16_recordtype_roundtrip() {
        for i in 0..100 {
            assert_eq!(u16::from(RecordType::from(i)), i);
        }
    }

    #[test]
    fn u16_recordclass_roundtrip() {
        for i in 0..100 {
            assert_eq!(u16::from(RecordClass::from(i)), i);
        }
    }
}

#[cfg(test)]
pub mod test_util {
    use super::*;

    pub fn domain(name: &str) -> DomainName {
        DomainName::from_dotted_string(name).unwrap()
    }

    pub fn a_record(name: &str, octets: Vec<u8>) -> ResourceRecord {
        ResourceRecord {
            name: domain(name),
            rtype_with_data: RecordTypeWithData::A { octets },
            rclass: RecordClass::IN,
            ttl: 300,
        }
    }

    pub fn cname_record(name: &str, target_name: &str) -> ResourceRecord {
        ResourceRecord {
            name: domain(name),
            rtype_with_data: RecordTypeWithData::CNAME {
                cname: domain(target_name),
            },
            rclass: RecordClass::IN,
            ttl: 300,
        }
    }

    pub fn ns_record(superdomain_name: &str, nameserver_name: &str) -> ResourceRecord {
        ResourceRecord {
            name: domain(superdomain_name),
            rtype_with_data: RecordTypeWithData::NS {
                nsdname: domain(nameserver_name),
            },
            rclass: RecordClass::IN,
            ttl: 300,
        }
    }
}
