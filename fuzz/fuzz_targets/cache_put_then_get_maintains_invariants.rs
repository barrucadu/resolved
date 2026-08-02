#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_resolver::cache::Cache;
use dns_resolver::cache::test_util::assert_invariants;
use dns_types::protocol::types::{ResourceRecord, RecordClass, QueryType};

fuzz_target!(|rrs: Vec<ResourceRecord>| {
    let mut cache = Cache::new();
    let mut queries = Vec::new();

    for rr in rrs {
        let mut rr = rr.clone();
        rr.rclass = RecordClass::IN;
        cache.insert(&rr);
        queries.push((
            rr.name.clone(),
            QueryType::Record(rr.rtype_with_data.rtype()),
        ));
    }
    for (name, qtype) in queries {
        cache.get_without_checking_expiration(&name, qtype);
    }

    assert_invariants(&cache);
});
