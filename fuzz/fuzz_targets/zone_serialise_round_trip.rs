#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_types::zones::types::Zone;

fuzz_target!(|zone: Zone| {
    let serialised = zone.serialise();
    if let Ok(deserialised) = Zone::deserialise(&serialised) {
        assert_eq!(zone, deserialised);
    } else {
        panic!("expected successful deserialisation");
    }
});
