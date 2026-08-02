#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_resolver::cache::Cache;
use dns_resolver::cache::test_util::assert_invariants;
use dns_types::protocol::types::{ResourceRecord, RecordClass};

fuzz_target!(|rrs: Vec<ResourceRecord>| {
    let mut cache = Cache::new();

    for rr in rrs {
        let mut rr = rr.clone();
        rr.rclass = RecordClass::IN;
        cache.insert(&rr);
    }

    assert_invariants(&cache);
});
