#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_types::zones::types::Zone;

fuzz_target!(|data: &str| {
    if let Ok(zone) = Zone::deserialise(data) {
        let serialised = zone.clone().serialise();
        let deserialised = Zone::deserialise(&serialised);
        assert_eq!(Ok(zone), deserialised);
    }
});
