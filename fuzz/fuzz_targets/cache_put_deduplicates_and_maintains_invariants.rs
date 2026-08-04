#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_resolver::cache::Cache;
use dns_resolver::cache::test_util::{assert_current_size, assert_invariants};
use dns_types::protocol::types::{ResourceRecord, RecordClass};

fuzz_target!(|rr: ResourceRecord| {
    let mut cache = Cache::new();
    let mut rr = rr.clone();
    rr.rclass = RecordClass::IN;

    cache.insert(rr.clone());
    cache.insert(rr);

    assert_current_size(1, &cache);
    assert_invariants(&cache);
});
