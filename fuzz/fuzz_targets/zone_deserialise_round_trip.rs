#![no_main]
use libfuzzer_sys::fuzz_target;

use resolved::zones::types::Zone;

fuzz_target!(|data: &str| {
    if let Ok(deserialised) = Zone::deserialise(data) {
        let serialised = deserialised.clone().serialise();
        if let Ok(re_deserialised) = Zone::deserialise(&serialised) {
            assert_eq!(deserialised, re_deserialised);
        } else {
            panic!("expected successful re-deserialisation");
        }
    }
});
