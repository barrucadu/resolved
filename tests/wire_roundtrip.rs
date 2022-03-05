use fake::{Fake, Faker};

use resolved::protocol::deserialise::ConsumableBuffer;
use resolved::protocol::serialise::WritableBuffer;
use resolved::protocol::wire_types::*;

#[test]
fn roundtrip_message() {
    for _ in 0..100 {
        let original = arbitrary_message();
        let deserialised = Message::from_octets(&original.clone().to_octets());

        assert_eq!(Ok(original), deserialised);
    }
}

#[test]
fn roundtrip_header() {
    for _ in 0..100 {
        let original = arbitrary_header();

        let mut buffer = WritableBuffer::default();
        original.clone().serialise(&mut buffer);
        let deserialised = Header::deserialise(&mut ConsumableBuffer::new(&buffer.octets));

        assert_eq!(Ok(original), deserialised);
    }
}

#[test]
fn roundtrip_question() {
    for _ in 0..100 {
        let original = arbitrary_question();

        let mut buffer = WritableBuffer::default();
        original.clone().serialise(&mut buffer);
        let deserialised = Question::deserialise(0, &mut ConsumableBuffer::new(&buffer.octets));

        assert_eq!(Ok(original), deserialised);
    }
}

#[test]
fn roundtrip_resourcerecord() {
    for _ in 0..100 {
        let original = arbitrary_resourcerecord();

        let mut buffer = WritableBuffer::default();
        original.clone().serialise(&mut buffer);
        let deserialised =
            ResourceRecord::deserialise(0, &mut ConsumableBuffer::new(&buffer.octets));

        assert_eq!(Ok(original), deserialised);
    }
}

#[test]
fn roundtrip_domainname() {
    for _ in 0..100 {
        let original = arbitrary_domainname();

        let mut buffer = WritableBuffer::default();
        original.clone().serialise(&mut buffer);
        let deserialised = DomainName::deserialise(0, &mut ConsumableBuffer::new(&buffer.octets));

        assert_eq!(Ok(original), deserialised);
    }
}

fn arbitrary_message() -> Message {
    let mut header = arbitrary_header();
    // keep runtime sane
    header.qdcount = (0..10).fake();
    header.ancount = (0..10).fake();
    header.nscount = (0..10).fake();
    header.arcount = (0..10).fake();

    let mut questions = Vec::with_capacity(header.qdcount as usize);
    let mut answers = Vec::with_capacity(header.ancount as usize);
    let mut authority = Vec::with_capacity(header.nscount as usize);
    let mut additional = Vec::with_capacity(header.arcount as usize);

    for _ in 0..header.qdcount {
        questions.push(arbitrary_question());
    }
    for _ in 0..header.ancount {
        answers.push(arbitrary_resourcerecord());
    }
    for _ in 0..header.nscount {
        authority.push(arbitrary_resourcerecord());
    }
    for _ in 0..header.arcount {
        additional.push(arbitrary_resourcerecord());
    }

    Message {
        header,
        questions,
        answers,
        authority,
        additional,
    }
}

fn arbitrary_header() -> Header {
    Header {
        id: Faker.fake(),
        is_response: Faker.fake(),
        opcode: arbitrary_opcode(),
        is_authoritative: Faker.fake(),
        is_truncated: Faker.fake(),
        recursion_desired: Faker.fake(),
        recursion_available: Faker.fake(),
        rcode: arbitrary_rcode(),
        qdcount: Faker.fake(),
        ancount: Faker.fake(),
        nscount: Faker.fake(),
        arcount: Faker.fake(),
    }
}

fn arbitrary_question() -> Question {
    Question {
        name: arbitrary_domainname(),
        qtype: arbitrary_querytype(),
        qclass: arbitrary_queryclass(),
    }
}

fn arbitrary_resourcerecord() -> ResourceRecord {
    ResourceRecord {
        name: arbitrary_domainname(),
        rtype_with_data: arbitrary_recordtypewithdata(),
        rclass: arbitrary_recordclass(),
        ttl: Faker.fake(),
    }
}

fn arbitrary_recordtypewithdata() -> RecordTypeWithData {
    // this should match the `RecordTypeWithData` deserialisation
    match arbitrary_recordtype() {
        RecordType::A => RecordTypeWithData::A {
            octets: arbitrary_octets((0..64).fake()),
        },
        RecordType::NS => RecordTypeWithData::NS {
            nsdname: arbitrary_domainname(),
        },
        RecordType::MD => RecordTypeWithData::MD {
            madname: arbitrary_domainname(),
        },
        RecordType::MF => RecordTypeWithData::MF {
            madname: arbitrary_domainname(),
        },
        RecordType::CNAME => RecordTypeWithData::CNAME {
            cname: arbitrary_domainname(),
        },
        RecordType::SOA => RecordTypeWithData::SOA {
            mname: arbitrary_domainname(),
            rname: arbitrary_domainname(),
            serial: Faker.fake(),
            refresh: Faker.fake(),
            retry: Faker.fake(),
            expire: Faker.fake(),
            minimum: Faker.fake(),
        },
        RecordType::MB => RecordTypeWithData::MB {
            madname: arbitrary_domainname(),
        },
        RecordType::MG => RecordTypeWithData::MG {
            mdmname: arbitrary_domainname(),
        },
        RecordType::MR => RecordTypeWithData::MR {
            newname: arbitrary_domainname(),
        },
        RecordType::NULL => RecordTypeWithData::NULL {
            octets: arbitrary_octets((0..64).fake()),
        },
        RecordType::WKS => RecordTypeWithData::WKS {
            octets: arbitrary_octets((0..64).fake()),
        },
        RecordType::PTR => RecordTypeWithData::PTR {
            ptrdname: arbitrary_domainname(),
        },
        RecordType::HINFO => RecordTypeWithData::HINFO {
            octets: arbitrary_octets((0..64).fake()),
        },
        RecordType::MINFO => RecordTypeWithData::MINFO {
            rmailbx: arbitrary_domainname(),
            emailbx: arbitrary_domainname(),
        },
        RecordType::MX => RecordTypeWithData::MX {
            preference: Faker.fake(),
            exchange: arbitrary_domainname(),
        },
        RecordType::TXT => RecordTypeWithData::TXT {
            octets: arbitrary_octets((0..64).fake()),
        },
        RecordType::Unknown(tag) => RecordTypeWithData::Unknown {
            tag,
            octets: arbitrary_octets((0..64).fake()),
        },
    }
}

fn arbitrary_domainname() -> DomainName {
    let num_labels = (1..5).fake::<usize>();
    let mut labels = Vec::<Vec<u8>>::new();
    let mut octets = Vec::<u8>::new();

    for _ in 0..num_labels {
        let label_len = (1..63).fake();
        let mut label = Vec::with_capacity(label_len as usize);
        octets.push(label_len);

        for _ in 0..label_len {
            let octet = Faker.fake::<u8>().to_ascii_lowercase();
            label.push(octet);
            octets.push(octet);
        }

        labels.push(label);
    }

    labels.push(Vec::new());
    octets.push(0);

    DomainName { labels, octets }
}

fn arbitrary_opcode() -> Opcode {
    // opcode is a 4-bit field
    (Faker.fake::<u8>() & 0b00001111).into()
}

fn arbitrary_rcode() -> Rcode {
    // rcode is a 4-bit field
    (Faker.fake::<u8>() & 0b00001111).into()
}

fn arbitrary_querytype() -> QueryType {
    Faker.fake::<u16>().into()
}
fn arbitrary_queryclass() -> QueryClass {
    Faker.fake::<u16>().into()
}

fn arbitrary_recordtype() -> RecordType {
    Faker.fake::<u16>().into()
}
fn arbitrary_recordclass() -> RecordClass {
    Faker.fake::<u16>().into()
}

fn arbitrary_octets(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(Faker.fake());
    }
    out
}
