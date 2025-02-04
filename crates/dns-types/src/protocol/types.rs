use bytes::{BufMut, Bytes, BytesMut};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Maximum encoded length of a domain name.  The number of labels
/// plus sum of the lengths of the labels.
pub const DOMAINNAME_MAX_LEN: usize = 255;

/// Maximum length of a single label in a domain name.
pub const LABEL_MAX_LEN: usize = 63;

/// Octet mask for the QR flag being set (response).
pub const HEADER_MASK_QR: u8 = 0b1000_0000;

/// Octet mask for the opcode field.
pub const HEADER_MASK_OPCODE: u8 = 0b0111_1000;

/// Offset for the opcode field.
pub const HEADER_OFFSET_OPCODE: usize = 3;

/// Octet mask for the AA flag being set (authoritative)
pub const HEADER_MASK_AA: u8 = 0b0000_0100;

/// Octet mask for the TC flag being set (truncated)
pub const HEADER_MASK_TC: u8 = 0b0000_0010;

/// Octet mask for the RD flag being set (desired)
pub const HEADER_MASK_RD: u8 = 0b0000_0001;

/// Octet mask for the RA flag being set (available)
pub const HEADER_MASK_RA: u8 = 0b1000_0000;

/// Octet mask for the rcode field.
pub const HEADER_MASK_RCODE: u8 = 0b0000_1111;

/// Offset for the rcode field.
pub const HEADER_OFFSET_RCODE: usize = 0;

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
#[cfg_attr(any(feature = "test-util", test), derive(arbitrary::Arbitrary))]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

impl Message {
    pub fn make_response(&self) -> Self {
        Self {
            header: Header {
                id: self.header.id,
                is_response: true,
                opcode: self.header.opcode,
                is_authoritative: false,
                is_truncated: false,
                recursion_desired: self.header.recursion_desired,
                recursion_available: true,
                rcode: Rcode::NoError,
            },
            questions: self.questions.clone(),
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
                recursion_available: true,
                rcode: Rcode::FormatError,
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
            },
            questions: vec![question],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }
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
///
/// The QECOUNT, ANCOUNT, NSCOUNT, and ARCOUNT fields are omitted from this
/// type, as they are only used during serialisation and deserialisation and can
/// be inferred from the other `Message` fields.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(any(feature = "test-util", test), derive(arbitrary::Arbitrary))]
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

    /// Truncation - specifies that this message was truncated due to
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
    ///   the query.
    ///
    /// - `2` Server failure - The name server was unable to process this query
    ///   due to a problem with the name server.
    ///
    /// - `3` Name Error - Meaningful only for responses from an authoritative
    ///   name server, this code signifies that the domain name referenced in
    ///   the query does not exist.
    ///
    /// - `4` Not Implemented - The name server does not support the requested
    ///   kind of query.
    ///
    /// - `5` Refused - The name server refuses to perform the specified
    ///   operation for policy reasons.  For example, a name server may not wish
    ///   to provide the information to the particular requester, or a name
    ///   server may not wish to perform a particular operation (e.g., zone
    ///   transfer) for particular data.
    ///
    /// - `6-15` Reserved for future use.
    pub rcode: Rcode,
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
#[cfg_attr(any(feature = "test-util", test), derive(arbitrary::Arbitrary))]
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
    pub fn is_unknown(&self) -> bool {
        self.qtype.is_unknown() || self.qclass.is_unknown()
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.name.to_dotted_string(),
            self.qclass,
            self.qtype
        )
    }
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
#[cfg_attr(any(feature = "test-util", test), derive(arbitrary::Arbitrary))]
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
    pub fn is_unknown(&self) -> bool {
        self.rtype_with_data.is_unknown() || self.rclass.is_unknown()
    }

    pub fn matches(&self, question: &Question) -> bool {
        self.rtype_with_data.matches(question.qtype) && self.rclass.matches(question.qclass)
    }
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
    A { address: Ipv4Addr },

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
    NULL { octets: Bytes },

    /// This application does not interpret `WKS` records.
    WKS { octets: Bytes },

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
    HINFO { octets: Bytes },

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
    TXT { octets: Bytes },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    ADDRESS                    |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `ADDRESS` is a 128 bit Internet address.
    AAAA { address: Ipv6Addr },

    /// ```text
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                   PRIORITY                    |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    WEIGHT                     |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                     PORT                      |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                    TARGET                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// Where `PRIORITY` is a 16 bit integer which specifies the order
    /// (lowest first) in which clients must attempt to use these RRs.
    ///
    /// Where `WEIGHT` is a 16 bit integer which specifies the
    /// preference given to this RR amongst others of the same
    /// priority.
    ///
    /// Where `PORT` is a 16 bit integer defining the port to contact
    /// the service on.
    ///
    /// Where `TARGET` is the domain name the service may be found at.
    /// This should point to a domain name that has an address record
    /// (A or AAAA) directly, rather than a domain name which has a
    /// CNAME or other alias type.  But this is not enforced.
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: DomainName,
    },

    /// Any other record.
    Unknown {
        tag: RecordTypeUnknown,
        octets: Bytes,
    },
}

impl RecordTypeWithData {
    pub fn is_unknown(&self) -> bool {
        self.rtype().is_unknown()
    }

    pub fn matches(&self, qtype: QueryType) -> bool {
        self.rtype().matches(qtype)
    }

    pub fn rtype(&self) -> RecordType {
        match self {
            RecordTypeWithData::A { .. } => RecordType::A,
            RecordTypeWithData::NS { .. } => RecordType::NS,
            RecordTypeWithData::MD { .. } => RecordType::MD,
            RecordTypeWithData::MF { .. } => RecordType::MF,
            RecordTypeWithData::CNAME { .. } => RecordType::CNAME,
            RecordTypeWithData::SOA { .. } => RecordType::SOA,
            RecordTypeWithData::MB { .. } => RecordType::MB,
            RecordTypeWithData::MG { .. } => RecordType::MG,
            RecordTypeWithData::MR { .. } => RecordType::MR,
            RecordTypeWithData::NULL { .. } => RecordType::NULL,
            RecordTypeWithData::WKS { .. } => RecordType::WKS,
            RecordTypeWithData::PTR { .. } => RecordType::PTR,
            RecordTypeWithData::HINFO { .. } => RecordType::HINFO,
            RecordTypeWithData::MINFO { .. } => RecordType::MINFO,
            RecordTypeWithData::MX { .. } => RecordType::MX,
            RecordTypeWithData::TXT { .. } => RecordType::TXT,
            RecordTypeWithData::AAAA { .. } => RecordType::AAAA,
            RecordTypeWithData::SRV { .. } => RecordType::SRV,
            RecordTypeWithData::Unknown { tag, .. } => RecordType::Unknown(*tag),
        }
    }
}

#[cfg(any(feature = "test-util", test))]
impl<'a> arbitrary::Arbitrary<'a> for RecordTypeWithData {
    // this is pretty verbose but it feels like a better way to guarantee the
    // max size of the `Bytes`s than adding a wrapper type
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0..=128)?;
        let octets = Bytes::copy_from_slice(u.bytes(len)?);

        let rtype_with_data = match u.arbitrary::<RecordType>()? {
            RecordType::A => RecordTypeWithData::A {
                address: u.arbitrary()?,
            },
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
            RecordType::AAAA => RecordTypeWithData::AAAA {
                address: u.arbitrary()?,
            },
            RecordType::SRV => RecordTypeWithData::SRV {
                priority: u.arbitrary()?,
                weight: u.arbitrary()?,
                port: u.arbitrary()?,
                target: u.arbitrary()?,
            },
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

impl Opcode {
    pub fn is_reserved(&self) -> bool {
        matches!(self, Opcode::Reserved(_))
    }
}

impl From<u8> for Opcode {
    fn from(octet: u8) -> Self {
        match octet & 0b0000_1111 {
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

#[cfg(any(feature = "test-util", test))]
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

impl Rcode {
    pub fn is_reserved(&self) -> bool {
        matches!(self, Rcode::Reserved(_))
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Rcode::NoError => write!(f, "no-error"),
            Rcode::FormatError => write!(f, "format-error"),
            Rcode::ServerFailure => write!(f, "server-failure"),
            Rcode::NameError => write!(f, "name-error"),
            Rcode::NotImplemented => write!(f, "not-implemented"),
            Rcode::Refused => write!(f, "refused"),
            Rcode::Reserved(_) => write!(f, "reserved"),
        }
    }
}

impl From<u8> for Rcode {
    fn from(octet: u8) -> Self {
        match octet & 0b0000_1111 {
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

#[cfg(any(feature = "test-util", test))]
impl<'a> arbitrary::Arbitrary<'a> for Rcode {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u8>()?))
    }
}

/// A domain name is a sequence of labels, where each label is a
/// length octet followed by that number of octets.
///
/// A label must be 63 octets or shorter.  A name must be 255 octets
/// or shorter in total, including both length and label octets.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DomainName {
    pub labels: Vec<Label>,
    // INVARIANT: len == len(labels) + sum(map(len, labels))
    pub len: usize,
}

impl DomainName {
    pub fn root_domain() -> Self {
        DomainName {
            labels: vec![Label::new()],
            len: 1,
        }
    }

    pub fn is_root(&self) -> bool {
        self.len == 1 && self.labels[0].is_empty()
    }

    pub fn is_subdomain_of(&self, other: &DomainName) -> bool {
        self.labels.ends_with(&other.labels)
    }

    pub fn make_subdomain_of(&self, origin: &Self) -> Option<Self> {
        let mut labels = self.labels.clone();
        labels.pop();
        labels.append(&mut origin.labels.clone());
        DomainName::from_labels(labels)
    }

    pub fn to_dotted_string(&self) -> String {
        if self.is_root() {
            return ".".to_string();
        }

        let mut out = String::with_capacity(self.len);
        let mut first = true;
        for label in &self.labels {
            if first {
                first = false;
            } else {
                out.push('.');
            }
            for octet in &label.octets {
                out.push(*octet as char);
            }
        }

        out
    }

    pub fn from_relative_dotted_string(origin: &Self, s: &str) -> Option<Self> {
        if s.is_empty() {
            Some(origin.clone())
        } else if s.to_string().ends_with('.') {
            Self::from_dotted_string(s)
        } else {
            let suffix = origin.to_dotted_string();
            if suffix.starts_with('.') {
                Self::from_dotted_string(&format!("{s}{suffix}"))
            } else {
                Self::from_dotted_string(&format!("{s}.{suffix}"))
            }
        }
    }

    pub fn from_dotted_string(s: &str) -> Option<Self> {
        if s == "." {
            return Some(Self::root_domain());
        }

        let chunks = s.split('.').collect::<Vec<_>>();
        let mut labels = Vec::with_capacity(chunks.len());

        for (i, label_chars) in chunks.iter().enumerate() {
            if label_chars.is_empty() && i != chunks.len() - 1 {
                return None;
            }

            match label_chars.as_bytes().try_into() {
                Ok(label) => labels.push(label),
                Err(_) => return None,
            }
        }

        Self::from_labels(labels)
    }

    pub fn from_labels(labels: Vec<Label>) -> Option<Self> {
        if labels.is_empty() {
            return None;
        }

        let mut len = labels.len();
        let mut blank_label = false;

        for label in &labels {
            if blank_label {
                return None;
            }

            blank_label |= label.is_empty();
            len += label.len() as usize;
        }

        if blank_label && len <= DOMAINNAME_MAX_LEN {
            Some(Self { labels, len })
        } else {
            None
        }
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainName")
            .field("to_dotted_string()", &self.to_dotted_string())
            .finish()
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.to_dotted_string())
    }
}

impl FromStr for DomainName {
    type Err = DomainNameFromStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(domain) = DomainName::from_dotted_string(s) {
            Ok(domain)
        } else {
            Err(DomainNameFromStr::NoParse)
        }
    }
}

/// Errors that can arise when converting a `&str` into a `DomainName`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum DomainNameFromStr {
    NoParse,
}

impl fmt::Display for DomainNameFromStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "could not parse string to domain name")
    }
}

impl std::error::Error for DomainNameFromStr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(any(feature = "test-util", test))]
impl<'a> arbitrary::Arbitrary<'a> for DomainName {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_labels = u.int_in_range::<usize>(0..=10)?;
        let mut labels = Vec::new();
        for _ in 0..num_labels {
            labels.push(u.arbitrary()?);
        }
        labels.push(Label::new());
        Ok(DomainName::from_labels(labels).unwrap())
    }
}

/// A label is just a sequence of octets, which are compared as
/// case-insensitive ASCII.  A label can be no longer than 63 octets.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Label {
    /// Private to this module so constructing an invalid `Label` is
    /// impossible.
    octets: Bytes,
}

impl Label {
    /// Create a new, empty, label.
    pub fn new() -> Self {
        Self {
            octets: Bytes::new(),
        }
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn len(&self) -> u8 {
        // safe as the `TryFrom` ensures a label is <= 63 bytes
        self.octets.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }

    pub fn octets(&self) -> &Bytes {
        &self.octets
    }
}

impl Default for Label {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<&[u8]> for Label {
    type Error = LabelTryFromOctetsError;

    fn try_from(mixed_case_octets: &[u8]) -> Result<Self, Self::Error> {
        if mixed_case_octets.len() > LABEL_MAX_LEN {
            return Err(LabelTryFromOctetsError::TooLong);
        }

        Ok(Self {
            octets: Bytes::copy_from_slice(&mixed_case_octets.to_ascii_lowercase()),
        })
    }
}

#[cfg(any(feature = "test-util", test))]
impl<'a> arbitrary::Arbitrary<'a> for Label {
    // only generates non-empty labels
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Label> {
        let label_len = u.int_in_range::<u8>(1..=20)?;
        let mut octets = BytesMut::with_capacity(label_len.into());
        let bs = u.bytes(label_len.into())?;
        for b in bs {
            let ascii_byte = if b.is_ascii() { *b } else { *b % 128 };
            octets.put_u8(
                if ascii_byte == b'.'
                    || ascii_byte == b'*'
                    || ascii_byte == b'@'
                    || ascii_byte == b'#'
                    || (ascii_byte as char).is_whitespace()
                {
                    b'x'
                } else {
                    ascii_byte.to_ascii_lowercase()
                },
            );
        }
        Ok(Self {
            octets: octets.freeze(),
        })
    }
}

/// Errors that can arise when converting a `[u8]` into a `Label`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum LabelTryFromOctetsError {
    TooLong,
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

impl QueryType {
    pub fn is_unknown(&self) -> bool {
        match self {
            QueryType::Record(rtype) => rtype.is_unknown(),
            _ => false,
        }
    }
}

impl fmt::Display for QueryType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QueryType::Record(rtype) => rtype.fmt(f),
            QueryType::AXFR => write!(f, "AXFR"),
            QueryType::MAILA => write!(f, "MAILA"),
            QueryType::MAILB => write!(f, "MAILB"),
            QueryType::Wildcard => write!(f, "ANY"),
        }
    }
}

impl FromStr for QueryType {
    type Err = RecordTypeFromStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AXFR" => Ok(QueryType::AXFR),
            "MAILA" => Ok(QueryType::MAILA),
            "MAILB" => Ok(QueryType::MAILB),
            "ANY" => Ok(QueryType::Wildcard),
            _ => RecordType::from_str(s).map(QueryType::Record),
        }
    }
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

#[cfg(any(feature = "test-util", test))]
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

impl QueryClass {
    pub fn is_unknown(&self) -> bool {
        match self {
            QueryClass::Record(rclass) => rclass.is_unknown(),
            QueryClass::Wildcard => false,
        }
    }
}

impl fmt::Display for QueryClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QueryClass::Record(rclass) => rclass.fmt(f),
            QueryClass::Wildcard => write!(f, "ANY"),
        }
    }
}

impl FromStr for QueryClass {
    type Err = RecordClassFromStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ANY" => Ok(QueryClass::Wildcard),
            _ => RecordClass::from_str(s).map(QueryClass::Record),
        }
    }
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

#[cfg(any(feature = "test-util", test))]
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
    AAAA,
    SRV,
    Unknown(RecordTypeUnknown),
}

/// A struct with a private constructor, to ensure invalid `RecordType`s
/// cannot be created.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RecordTypeUnknown(u16);

impl RecordType {
    pub fn is_unknown(&self) -> bool {
        matches!(self, RecordType::Unknown(_))
    }

    pub fn matches(&self, qtype: QueryType) -> bool {
        match qtype {
            QueryType::Wildcard => true,
            QueryType::Record(rtype) => rtype == *self,
            _ => false,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::NS => write!(f, "NS"),
            RecordType::MD => write!(f, "MD"),
            RecordType::MF => write!(f, "MF"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::MB => write!(f, "MB"),
            RecordType::MG => write!(f, "MG"),
            RecordType::MR => write!(f, "MR"),
            RecordType::NULL => write!(f, "NULL"),
            RecordType::WKS => write!(f, "WKS"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::HINFO => write!(f, "HINFO"),
            RecordType::MINFO => write!(f, "MINFO"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::Unknown(RecordTypeUnknown(n)) => write!(f, "TYPE{n}"),
        }
    }
}

impl FromStr for RecordType {
    type Err = RecordTypeFromStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "A" => Ok(RecordType::A),
            "NS" => Ok(RecordType::NS),
            "MD" => Ok(RecordType::MD),
            "MF" => Ok(RecordType::MF),
            "CNAME" => Ok(RecordType::CNAME),
            "SOA" => Ok(RecordType::SOA),
            "MB" => Ok(RecordType::MB),
            "MG" => Ok(RecordType::MG),
            "MR" => Ok(RecordType::MR),
            "NULL" => Ok(RecordType::NULL),
            "WKS" => Ok(RecordType::WKS),
            "PTR" => Ok(RecordType::PTR),
            "HINFO" => Ok(RecordType::HINFO),
            "MINFO" => Ok(RecordType::MINFO),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "AAAA" => Ok(RecordType::AAAA),
            "SRV" => Ok(RecordType::SRV),
            _ => {
                if let Some(type_str) = s.strip_prefix("TYPE") {
                    if let Ok(type_num) = u16::from_str(type_str) {
                        Ok(RecordType::from(type_num))
                    } else {
                        Err(RecordTypeFromStr::BadType)
                    }
                } else {
                    Err(RecordTypeFromStr::NoParse)
                }
            }
        }
    }
}

/// Errors that can arise when converting a `&str` into a `RecordType`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum RecordTypeFromStr {
    BadType,
    NoParse,
}

impl fmt::Display for RecordTypeFromStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecordTypeFromStr::BadType => write!(f, "TYPE<num> number must be a u16"),
            RecordTypeFromStr::NoParse => write!(f, "could not parse string to type"),
        }
    }
}

impl std::error::Error for RecordTypeFromStr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

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
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
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
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::Unknown(RecordTypeUnknown(value)) => value,
        }
    }
}

#[cfg(any(feature = "test-util", test))]
impl<'a> arbitrary::Arbitrary<'a> for RecordType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u16>()?))
    }
}

/// Record classes are used by resource records and by queries.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RecordClass {
    IN,
    Unknown(RecordClassUnknown),
}

/// A struct with a private constructor, to ensure invalid
/// `RecordClass`es cannot be created.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RecordClassUnknown(u16);

impl RecordClass {
    pub fn is_unknown(&self) -> bool {
        matches!(self, RecordClass::Unknown(_))
    }

    pub fn matches(&self, qclass: QueryClass) -> bool {
        match qclass {
            QueryClass::Wildcard => true,
            QueryClass::Record(rclass) => rclass == *self,
        }
    }
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecordClass::IN => write!(f, "IN"),
            RecordClass::Unknown(RecordClassUnknown(n)) => write!(f, "CLASS{n}"),
        }
    }
}

impl FromStr for RecordClass {
    type Err = RecordClassFromStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "IN" => Ok(RecordClass::IN),
            _ => {
                if let Some(class_str) = s.strip_prefix("CLASS") {
                    if let Ok(class_num) = u16::from_str(class_str) {
                        Ok(RecordClass::from(class_num))
                    } else {
                        Err(RecordClassFromStr::BadClass)
                    }
                } else {
                    Err(RecordClassFromStr::NoParse)
                }
            }
        }
    }
}

/// Errors that can arise when converting a `&str` into a `RecordClass`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum RecordClassFromStr {
    BadClass,
    NoParse,
}

impl fmt::Display for RecordClassFromStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecordClassFromStr::BadClass => write!(f, "CLASS<num> number must be a u16"),
            RecordClassFromStr::NoParse => write!(f, "could not parse string to class"),
        }
    }
}

impl std::error::Error for RecordClassFromStr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<u16> for RecordClass {
    fn from(value: u16) -> Self {
        match value {
            1 => RecordClass::IN,
            _ => RecordClass::Unknown(RecordClassUnknown(value)),
        }
    }
}

impl From<RecordClass> for u16 {
    fn from(value: RecordClass) -> Self {
        match value {
            RecordClass::IN => 1,
            RecordClass::Unknown(RecordClassUnknown(value)) => value,
        }
    }
}

#[cfg(any(feature = "test-util", test))]
impl<'a> arbitrary::Arbitrary<'a> for RecordClass {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u16>()?))
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::test_util::*;
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
    fn recordtype_unknown_implies_querytype_unknown() {
        for i in 0..100 {
            if RecordType::from(i).is_unknown() {
                assert!(QueryType::from(i).is_unknown());
            }
        }
    }

    #[test]
    fn u16_recordclass_roundtrip() {
        for i in 0..100 {
            assert_eq!(u16::from(RecordClass::from(i)), i);
        }
    }

    #[test]
    fn recordclass_unknown_implies_queryclass_unknown() {
        for i in 0..100 {
            if RecordClass::from(i).is_unknown() {
                assert!(QueryClass::from(i).is_unknown());
            }
        }
    }

    #[test]
    fn domainname_root_conversions() {
        assert_eq!(
            Some(DomainName::root_domain()),
            DomainName::from_dotted_string(".")
        );

        assert_eq!(
            Some(DomainName::root_domain()),
            DomainName::from_labels(vec![Label::new()])
        );

        assert_eq!(".", DomainName::root_domain().to_dotted_string());
    }

    #[test]
    fn from_relative_dotted_string_empty() {
        let origin = domain("com.");
        assert_eq!(
            Some(domain("com.")),
            DomainName::from_relative_dotted_string(&origin, "")
        );
    }

    #[test]
    fn from_relative_dotted_string_absolute() {
        let origin = domain("com.");
        assert_eq!(
            Some(domain("www.example.com.")),
            DomainName::from_relative_dotted_string(&origin, "www.example.com.")
        );
    }

    #[test]
    fn from_relative_dotted_string_relative() {
        let origin = domain("com.");
        assert_eq!(
            Some(domain("www.example.com.")),
            DomainName::from_relative_dotted_string(&origin, "www.example")
        );
    }

    #[test]
    fn make_subdomain_is_subdomain() {
        let sub = domain("foo.");
        let apex = domain("bar.");
        let combined = sub.make_subdomain_of(&apex);

        assert_eq!(Some(domain("foo.bar.")), combined);
        assert!(combined.unwrap().is_subdomain_of(&apex));
    }

    #[test]
    fn domainname_conversions() {
        let mut rng = rand::rng();
        for _ in 0..100 {
            let labels_len = rng.random_range(0..5);

            let mut dotted_string_input = String::new();
            let mut labels_input = Vec::with_capacity(labels_len);
            let mut output = String::new();

            for i in 0..labels_len {
                let label_len = rng.random_range(1..10);

                if i > 0 {
                    dotted_string_input.push('.');
                    output.push('.');
                }

                let mut octets = BytesMut::with_capacity(label_len);
                for _ in 0..label_len {
                    let mut chr = rng.random_range(32..126);

                    if chr == b'.'
                        || chr == b'*'
                        || chr == b'@'
                        || chr == b'#'
                        || (chr as char).is_whitespace()
                    {
                        chr = b'X';
                    }

                    octets.put_u8(chr);
                    dotted_string_input.push(chr as char);
                    output.push(chr.to_ascii_lowercase() as char);
                }
                labels_input.push(Label::try_from(&octets.freeze()[..]).unwrap());
            }

            labels_input.push(Label::new());
            dotted_string_input.push('.');
            output.push('.');

            assert_eq!(
                Some(output.clone()),
                DomainName::from_dotted_string(&dotted_string_input).map(|d| d.to_dotted_string())
            );

            assert_eq!(
                Some(output),
                DomainName::from_labels(labels_input.clone()).map(|d| d.to_dotted_string())
            );

            assert_eq!(
                DomainName::from_dotted_string(&dotted_string_input).map(|d| d.to_dotted_string()),
                DomainName::from_labels(labels_input).map(|d| d.to_dotted_string())
            );
        }
    }
}

#[cfg(any(feature = "test-util", test))]
#[allow(clippy::missing_panics_doc)]
pub mod test_util {
    use super::*;

    use arbitrary::{Arbitrary, Unstructured};
    use rand::Rng;

    pub fn arbitrary_resourcerecord() -> ResourceRecord {
        let mut rng = rand::rng();
        for size in [128, 256, 512, 1024, 2048, 4096] {
            let mut buf = BytesMut::with_capacity(size);
            for _ in 0..size {
                buf.put_u8(rng.random());
            }

            if let Ok(rr) = ResourceRecord::arbitrary(&mut Unstructured::new(&buf.freeze())) {
                return rr;
            }
        }

        panic!("could not generate arbitrary value!");
    }

    pub fn domain(name: &str) -> DomainName {
        DomainName::from_dotted_string(name).unwrap()
    }

    pub fn a_record(name: &str, address: Ipv4Addr) -> ResourceRecord {
        ResourceRecord {
            name: domain(name),
            rtype_with_data: RecordTypeWithData::A { address },
            rclass: RecordClass::IN,
            ttl: 300,
        }
    }

    pub fn aaaa_record(name: &str, address: Ipv6Addr) -> ResourceRecord {
        ResourceRecord {
            name: domain(name),
            rtype_with_data: RecordTypeWithData::AAAA { address },
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

    pub fn unknown_record(name: &str, octets: &[u8]) -> ResourceRecord {
        ResourceRecord {
            name: domain(name),
            rtype_with_data: RecordTypeWithData::Unknown {
                tag: RecordTypeUnknown(100),
                octets: Bytes::copy_from_slice(octets),
            },
            rclass: RecordClass::IN,
            ttl: 300,
        }
    }
}
