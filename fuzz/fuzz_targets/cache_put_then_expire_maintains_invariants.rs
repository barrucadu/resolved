#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_resolver::cache::Cache;
use dns_resolver::cache::test_util::{assert_current_size, assert_expires, assert_invariants};
use dns_types::protocol::types::{ResourceRecord, RecordClass};
use dns_types::protocol::types::test_util::domain;

fuzz_target!(|rrs: Vec<(ResourceRecord, bool)>| {
    let mut cache = Cache::new();

    let mut expected_expired = 0;
    let mut expected_kept = 0;
    let mut i = 0;
    
    for (mut rr, expire) in rrs {
        // ensure each record has a unique name
        rr.name = rr.name.make_subdomain_of(&domain(&format!("{}.", i))).unwrap();
        rr.rclass = RecordClass::IN;
        if expire {
            rr.ttl = 0;
            expected_expired += 1;
        } else {
            rr.ttl = 300;
            expected_kept += 1;
        }
        cache.insert(rr);
        i += 1;
    }

    assert_expires(expected_expired, &mut cache);
    assert_current_size(expected_kept, &cache);
    assert_invariants(&cache);
});
