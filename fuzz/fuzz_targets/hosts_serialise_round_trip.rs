#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_types::hosts::types::Hosts;

fuzz_target!(|hosts: Hosts| {
    let serialised = hosts.serialise();
    let deserialised = Hosts::deserialise(&serialised);
    assert_eq!(Ok(hosts), deserialised);
});
