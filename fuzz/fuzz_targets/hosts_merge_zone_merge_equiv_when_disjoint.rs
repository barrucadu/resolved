#![no_main]
use libfuzzer_sys::fuzz_target;

use std::convert::TryInto;

use dns_types::hosts::types::Hosts;
use dns_types::protocol::types::DomainName;
use dns_types::protocol::types::test_util::domain;
use dns_types::zones::types::Zone;

fn hosts_with_apex(arbitrary: Hosts, apex: DomainName) -> Hosts {
    let mut out = Hosts::new();
    for (k, v) in arbitrary.v4 {
        out.v4.insert(k.make_subdomain_of(&apex).unwrap(), v);
    }
    for (k, v) in arbitrary.v6 {
        out.v6.insert(k.make_subdomain_of(&apex).unwrap(), v);
    }
    out
}

fuzz_target!(|hosts: (Hosts, Hosts)| {
    let disjoint_hosts1 = hosts_with_apex(hosts.0, domain("hosts1."));
    let disjoint_hosts2 = hosts_with_apex(hosts.1, domain("hosts2."));

    let mut combined_hosts = disjoint_hosts1.clone();
    combined_hosts.merge(disjoint_hosts2.clone());

    let combined_zone_direct = Zone::from(combined_hosts.clone());
    let mut combined_zone_indirect = Zone::from(disjoint_hosts1);
    combined_zone_indirect.merge(disjoint_hosts2.into()).unwrap();

    assert_eq!(combined_zone_direct, combined_zone_indirect);
    assert_eq!(Ok(combined_hosts), combined_zone_direct.try_into());
});
