#![no_main]
use libfuzzer_sys::fuzz_target;

use std::convert::TryFrom;

use dns_types::hosts::types::Hosts;
use dns_types::zones::types::Zone;

fuzz_target!(|hosts: Hosts| {
    if let Ok(actual) = Hosts::try_from(Zone::from(hosts.clone())) {
        assert_eq!(hosts, actual);
    } else {
        panic!("expected round-trip");
    }
});
