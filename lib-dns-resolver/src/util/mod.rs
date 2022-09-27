pub mod fs;
pub mod nameserver;
pub mod net;
pub mod types;

#[cfg(test)]
pub mod test_util {
    use dns_types::protocol::types::test_util::*;
    use dns_types::protocol::types::*;
    use dns_types::zones::types::*;
    use std::net::Ipv4Addr;

    pub fn zones() -> Zones {
        let mut zone_na = Zone::default();
        zone_na.insert(
            &domain("blocked.example.com."),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(0, 0, 0, 0),
            },
            300,
        );
        zone_na.insert(
            &domain("cname-and-a.example.com."),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(1, 1, 1, 1),
            },
            300,
        );
        zone_na.insert(
            &domain("cname-and-a.example.com."),
            RecordTypeWithData::CNAME {
                cname: domain("cname-target.example.com."),
            },
            300,
        );
        zone_na.insert(
            &domain("a.example.com."),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(1, 1, 1, 1),
            },
            300,
        );
        zone_na.insert(
            &domain("delegated.example.com."),
            RecordTypeWithData::NS {
                nsdname: domain("ns.delegated.example.com."),
            },
            300,
        );
        zone_na.insert(
            &domain("trailing-cname.example.com."),
            RecordTypeWithData::CNAME {
                cname: domain("somewhere-else.example.com."),
            },
            300,
        );

        let mut zone_a = Zone::new(
            domain("authoritative.example.com."),
            Some(SOA {
                mname: domain("mname."),
                rname: domain("rname."),
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0,
            }),
        );
        zone_a.insert(
            &domain("authoritative.example.com."),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(1, 1, 1, 1),
            },
            300,
        );
        zone_a.insert(
            &domain("cname-a.authoritative.example.com."),
            RecordTypeWithData::CNAME {
                cname: domain("authoritative.example.com."),
            },
            300,
        );
        zone_a.insert(
            &domain("cname-na.authoritative.example.com."),
            RecordTypeWithData::CNAME {
                cname: domain("a.example.com."),
            },
            300,
        );
        zone_a.insert(
            &domain("delegated.authoritative.example.com."),
            RecordTypeWithData::NS {
                nsdname: domain("ns.delegated.authoritative.example.com."),
            },
            300,
        );

        let mut zones = Zones::new();
        zones.insert(zone_na);
        zones.insert(zone_a);

        zones
    }
}
