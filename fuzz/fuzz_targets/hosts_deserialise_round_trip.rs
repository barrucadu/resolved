#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_types::hosts::types::Hosts;

fuzz_target!(|data: &str| {
    if let Ok(hosts) = Hosts::deserialise(data) {
        let serialised = hosts.clone().serialise();
        let deserialised = Hosts::deserialise(&serialised);
        assert_eq!(Ok(hosts), deserialised);
    }
});
