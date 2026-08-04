#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_resolver::cache::Cache;
use dns_resolver::cache::test_util::assert_cache_response;
use dns_types::protocol::types::{ResourceRecord, RecordClass, QueryType};

fuzz_target!(|rr: ResourceRecord| {
    let mut cache = Cache::new();
    let mut rr = rr.clone();
    rr.rclass = RecordClass::IN;
    cache.insert(rr.clone());

    assert_cache_response(
        &rr,
        &cache.get_without_checking_expiration(
            &rr.name,
            QueryType::Record(rr.rtype_with_data.rtype()),
        ),
    );
    assert_cache_response(
        &rr,
        &cache.get_without_checking_expiration(&rr.name, QueryType::Wildcard),
    );
});
