#![no_main]
use libfuzzer_sys::fuzz_target;

use resolved::hosts::types::Hosts;

fuzz_target!(|data: &str| {
    if let Ok(deserialised) = Hosts::deserialise(data) {
        let serialised = deserialised.clone().serialise();
        if let Ok(re_deserialised) = Hosts::deserialise(&serialised) {
            if deserialised != re_deserialised {
                panic!(
                    "\n   deserialised: {:?}\n\nre-deserialised: {:?}\n\n{:?}",
                    deserialised, re_deserialised, serialised
                );
            }
            assert_eq!(deserialised, re_deserialised);
        } else {
            panic!("expected successful re-deserialisation");
        }
    }
});
