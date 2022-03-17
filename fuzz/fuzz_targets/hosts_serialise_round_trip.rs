#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_types::hosts::types::Hosts;

fuzz_target!(|hosts: Hosts| {
    let serialised = hosts.serialise();
    if let Ok(deserialised) = Hosts::deserialise(&serialised) {
        assert_eq!(hosts, deserialised);
    } else {
        panic!(
            "expected successful deserialisation\n\n{:?}\n\n{:?}",
            hosts, serialised
        );
    }
});
