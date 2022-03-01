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
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
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
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
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
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
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
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Opcode {
    Standard,
    Inverse,
    Status,
    Reserved(u8),
}

/// What sort of response this is.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved(u8),
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

/// Query types are a superset of record types.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum QueryType {
    Record(RecordType),
    AXFR,
    MAILB,
    MAILA,
    Wildcard,
}

/// Query classes are a superset of record classes.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum QueryClass {
    Record(RecordClass),
    Wildcard,
}

/// Record types are used by resource records and by queries.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
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

/// Record classes are used by resource records and by queries.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum RecordClass {
    IN,
    CS,
    CH,
    HS,
    Unknown(u16),
}
