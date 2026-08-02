#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_resolver::cache::Cache;
use dns_resolver::cache::test_util::{assert_current_size, assert_invariants};
use dns_types::protocol::types::{ResourceRecord, RecordClass};
use dns_types::protocol::types::test_util::domain;

const DESIRED: usize = 25;

fuzz_target!(|rrs: Vec<(ResourceRecord, bool)>| {
    let mut cache = Cache::with_desired_size(DESIRED);

    let mut expected_expired: usize = 0;
    let mut num_records: usize = 0;
    
    for (rr, expire) in rrs {
        num_records += 1;
        let mut rr = rr.clone();
        // ensure each record has a unique name
        rr.name = rr.name.make_subdomain_of(&domain(&format!("{}.", num_records))).unwrap();
        rr.rclass = RecordClass::IN;
        if expire {
            rr.ttl = 0;
            expected_expired += 1;
        } else {
            rr.ttl = 300;
        }
        cache.insert(&rr);
    }

    // if expiry isn't enough, records must be pruned to fit the desired size
    let expected_pruned = (num_records - expected_expired).saturating_sub(DESIRED);

    let (overflow, current_size, expired, pruned) = cache.prune();
    assert_eq!(overflow, num_records > DESIRED);
    assert_eq!(expected_expired, expired);
    assert_eq!(expected_pruned, pruned);
    assert_current_size(current_size, &cache);
    assert_invariants(&cache);
});
