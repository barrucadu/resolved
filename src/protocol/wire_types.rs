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

/// A record type with its associated data.  This is so any pointers
/// in domain names will be expanded before further processing.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
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
        match octet {
            0 => Opcode::Standard,
            1 => Opcode::Inverse,
            2 => Opcode::Status,
            _ => Opcode::Reserved(OpcodeReserved(octet)),
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
        match octet {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            _ => Rcode::Reserved(RcodeReserved(octet)),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u8_opcode_roundtrip() {
        for i in 0..100 {
            assert_eq!(u8::from(Opcode::from(i)), i);
        }
    }

    #[test]
    fn u8_rcode_roundtrip() {
        for i in 0..100 {
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
