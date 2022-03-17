use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};

use dns_types::protocol::types::*;
use resolved::resolver::cache::Cache;

#[allow(non_snake_case)]
fn bench__insert__unique(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert/unique");
    for size in [1, 100, 1000] {
        let (rrs, _) = make_rrs(size, 300);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &rrs, |b, rrs| {
            b.iter(|| build_cache(size, rrs));
        });
    }
    group.finish();
}

#[allow(non_snake_case)]
fn bench__insert__duplicate(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert/duplicate");
    for size in [1, 100, 1000] {
        let rrs = {
            let mut out = Vec::with_capacity(size);
            let name1 = DomainName::from_dotted_string("www.source.example.com.").unwrap();
            let name2 = DomainName::from_dotted_string("www.target.example.com.").unwrap();
            let rr = ResourceRecord {
                name: name1,
                rtype_with_data: RecordTypeWithData::CNAME { cname: name2 },
                rclass: RecordClass::IN,
                ttl: 300,
            };
            for _ in 0..size {
                out.push(rr.clone());
            }
            out
        };

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &rrs, |b, rrs| {
            b.iter(|| build_cache(size, rrs));
        });
    }
    group.finish();
}

#[allow(non_snake_case)]
fn bench__get_without_checking_expiration__hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_without_checking_expiration/hit");
    for size in [1, 100, 1000] {
        let (rrs, queries) = make_rrs(size, 0);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &rrs, |b, rrs| {
            b.iter_batched(
                || build_cache(size, rrs),
                |mut cache| {
                    for (name, rtype) in &queries {
                        cache.get_without_checking_expiration(name, &QueryType::Record(*rtype));
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

#[allow(non_snake_case)]
fn bench__get_without_checking_expiration__miss(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_without_checking_expiration/miss");
    for size in [1, 100, 1000] {
        let (rrs, queries) = make_rrs(size, 0);
        let name = DomainName::from_dotted_string(
            "name.which.is.unlikely.to.coincidentally.be.randomly.generated.",
        )
        .unwrap();
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &rrs, |b, rrs| {
            b.iter_batched(
                || build_cache(size, rrs),
                |mut cache| {
                    for (_, rtype) in &queries {
                        cache.get_without_checking_expiration(&name, &QueryType::Record(*rtype));
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

#[allow(non_snake_case)]
fn bench__remove_expired(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove_expired");
    for size in [1, 100, 1000] {
        let (rrs, _) = make_rrs(size, 0);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &rrs, |b, rrs| {
            b.iter_batched(
                || build_cache(size, rrs),
                |mut cache| cache.remove_expired(),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

#[allow(non_snake_case)]
fn bench__prune(c: &mut Criterion) {
    let mut group = c.benchmark_group("prune");
    for size in [1, 100, 1000] {
        let (rrs, _) = make_rrs(size + 1, 300);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &rrs, |b, rrs| {
            b.iter_batched(
                || build_cache(1, rrs),
                |mut cache| cache.prune(),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn build_cache(size: usize, rrs: &[ResourceRecord]) -> Cache {
    let mut cache = Cache::with_desired_size(size);
    for rr in rrs {
        cache.insert(rr);
    }
    cache
}

fn make_rrs(size: usize, ttl: u32) -> (Vec<ResourceRecord>, Vec<(DomainName, RecordType)>) {
    let mut rrs = Vec::with_capacity(size);
    let mut queries = Vec::with_capacity(size);

    for i in 0..size {
        let name1 = DomainName::from_dotted_string(&format!("www-{:?}.source.example.com.", i / 2))
            .unwrap();
        let name2 = DomainName::from_dotted_string(&format!("www-{:?}.target.example.com.", i / 2))
            .unwrap();

        if i % 2 == 0 {
            queries.push((name1.clone(), RecordType::CNAME));
            rrs.push(ResourceRecord {
                name: name1,
                rtype_with_data: RecordTypeWithData::CNAME { cname: name2 },
                rclass: RecordClass::IN,
                ttl,
            });
        } else {
            queries.push((name1.clone(), RecordType::NS));
            rrs.push(ResourceRecord {
                name: name1,
                rtype_with_data: RecordTypeWithData::NS { nsdname: name2 },
                rclass: RecordClass::IN,
                ttl,
            });
        };
    }

    (rrs, queries)
}

criterion_group!(
    benches,
    bench__insert__unique,
    bench__insert__duplicate,
    bench__get_without_checking_expiration__hit,
    bench__get_without_checking_expiration__miss,
    bench__remove_expired,
    bench__prune
);
criterion_main!(benches);
