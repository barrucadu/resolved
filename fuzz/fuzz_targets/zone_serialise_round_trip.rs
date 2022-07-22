#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_types::zones::types::Zone;

fuzz_target!(|zone: Zone| {
    let serialised = zone.serialise();
    let deserialised = Zone::deserialise(&serialised);
    assert_eq!(Ok(zone), deserialised);
});
