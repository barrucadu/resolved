use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use std::net::Ipv4Addr;

use dns_types::protocol::types::*;

#[allow(non_snake_case)]
fn bench__question(c: &mut Criterion) {
    let message = Message::from_question(
        1234,
        Question {
            name: domain("www.example.com."),
            qtype: QueryType::Record(RecordType::A),
            qclass: QueryClass::Record(RecordClass::IN),
        },
    );

    c.bench_function("serialise/question", |b| {
        b.iter_batched(
            || message.clone(),
            |message| message.to_octets(),
            BatchSize::SmallInput,
        )
    });

    let serialised = message.to_octets().unwrap();
    c.bench_function("deserialise/question", |b| {
        b.iter(|| Message::from_octets(black_box(&serialised)))
    });
}

#[allow(non_snake_case)]
fn bench__answer__small(c: &mut Criterion) {
    let mut message = Message::from_question(
        1234,
        Question {
            name: domain("www.example.com."),
            qtype: QueryType::Record(RecordType::A),
            qclass: QueryClass::Record(RecordClass::IN),
        },
    )
    .make_response();

    message.answers = vec![a_record("www.example.com.", Ipv4Addr::new(1, 1, 1, 1))];

    c.bench_function("serialise/answer/small", |b| {
        b.iter_batched(
            || message.clone(),
            |message| message.to_octets(),
            BatchSize::SmallInput,
        )
    });

    let serialised = message.to_octets().unwrap();
    c.bench_function("deserialise/answer/small", |b| {
        b.iter(|| Message::from_octets(black_box(&serialised)))
    });
}

#[allow(non_snake_case)]
fn bench__answer__big(c: &mut Criterion) {
    let mut message = Message::from_question(
        1234,
        Question {
            name: domain("www.example.com."),
            qtype: QueryType::Record(RecordType::A),
            qclass: QueryClass::Record(RecordClass::IN),
        },
    )
    .make_response();

    let count = 128;

    for i in 0..count {
        message.answers.push(cname_record(
            "www.example.com.",
            &format!("www.cname-target-{:?}.example.com.", i),
        ));
    }
    for i in 0..count {
        message.authority.push(ns_record(
            &format!("cname-target-{:?}.example.com.", i),
            &format!("ns-{:?}.example.com.", i),
        ));
    }
    for i in 0..count {
        message.additional.push(a_record(
            &format!("ns-{:?}.example.com.", i),
            Ipv4Addr::new(1, 1, 1, 1),
        ));
    }

    c.bench_function("serialise/answer/big", |b| {
        b.iter_batched(
            || message.clone(),
            |message| message.to_octets(),
            BatchSize::SmallInput,
        )
    });

    let serialised = message.to_octets().unwrap();
    c.bench_function("deserialise/answer/big", |b| {
        b.iter(|| Message::from_octets(black_box(&serialised)))
    });
}

// TODO: reduce duplication with protocol::types::test_util
fn domain(name: &str) -> DomainName {
    DomainName::from_dotted_string(name).unwrap()
}

fn a_record(name: &str, address: Ipv4Addr) -> ResourceRecord {
    ResourceRecord {
        name: domain(name),
        rtype_with_data: RecordTypeWithData::A { address },
        rclass: RecordClass::IN,
        ttl: 300,
    }
}

fn cname_record(name: &str, target_name: &str) -> ResourceRecord {
    ResourceRecord {
        name: domain(name),
        rtype_with_data: RecordTypeWithData::CNAME {
            cname: domain(target_name),
        },
        rclass: RecordClass::IN,
        ttl: 300,
    }
}

fn ns_record(superdomain_name: &str, nameserver_name: &str) -> ResourceRecord {
    ResourceRecord {
        name: domain(superdomain_name),
        rtype_with_data: RecordTypeWithData::NS {
            nsdname: domain(nameserver_name),
        },
        rclass: RecordClass::IN,
        ttl: 300,
    }
}

criterion_group!(
    benches,
    bench__question,
    bench__answer__small,
    bench__answer__big,
);
criterion_main!(benches);
