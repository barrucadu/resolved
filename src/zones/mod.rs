use std::collections::HashMap;

use crate::protocol::wire_types::*;

/// A collection of zones.
#[derive(Debug, Clone)]
pub struct Zones {
    zones: HashMap<DomainName, Zone>,
}

impl Default for Zones {
    fn default() -> Self {
        Self::new()
    }
}

impl Zones {
    pub fn new() -> Self {
        Self {
            zones: HashMap::new(),
        }
    }

    /// Find the zone for a domain, if there is one.
    pub fn get(&self, name: &DomainName) -> Option<&Zone> {
        for i in 0..name.labels.len() {
            let labels = &name.labels[i..];
            if let Some(name) = DomainName::from_labels(labels.into()) {
                if let Some(zone) = self.zones.get(&name) {
                    return Some(zone);
                }
            }
        }

        None
    }

    /// Update or replace a zone.
    pub fn insert(&mut self, zone: Zone) {
        self.zones.insert(zone.apex.clone(), zone);
    }
}

/// A zone is a collection of records all belonging to the same domain
/// name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// The domain name which the records all belong to.
    apex: DomainName,

    /// The SOA record for this zone, if it is authoritative.
    soa: Option<SOA>,

    /// Records.  These are indexed by label, with the labels relative
    /// to the apex.  For example, if the apex is "barrucadu.co.uk",
    /// then records for "www.barrucadu.co.uk" would be indexed under
    /// "www".
    records: ZoneRecords,
}

impl Default for Zone {
    fn default() -> Self {
        Self::new(DomainName::root_domain(), None)
    }
}

impl Zone {
    /// Construct a new zone.
    ///
    /// If there is a `SOA` value, it is inserted as an RR at the root
    /// of the zone.
    pub fn new(apex: DomainName, soa: Option<SOA>) -> Self {
        let mut records = ZoneRecords::new();
        if let Some(soa) = &soa {
            let rr = soa.to_rr(&apex);
            records.insert(&[], rr.rtype_with_data, rr.rclass, rr.ttl);
        };

        Self { apex, soa, records }
    }

    /// Returns the apex domain.
    pub fn get_apex(&self) -> &DomainName {
        &self.apex
    }

    /// Returns true if the zone is authoritative.
    pub fn is_authoritative(&self) -> bool {
        self.soa.is_some()
    }

    /// Returns the SOA RR if the zone is authoritative.
    pub fn soa_rr(&self) -> Option<ResourceRecord> {
        self.soa.as_ref().map(|soa| soa.to_rr(&self.apex))
    }

    /// Get records matching a domain.  This domain MUST be a
    /// subdomain of the apex.
    ///
    /// Returns `None` if the domain does not exist.  This is distinct
    /// from `Some(Vec::new())`, which means that the domain does
    /// exist but has no matching records.  If the domain does not
    /// exist and this zone is authoritative, an authoritative
    /// NXDOMAIN response can be served to the user.
    pub fn get(
        &self,
        name: &DomainName,
        qtype: QueryType,
        qclass: QueryClass,
    ) -> Option<Vec<ResourceRecord>> {
        if !name.is_subdomain_of(&self.apex) {
            return None;
        }

        let relative_domain = &name.labels[0..name.labels.len() - self.apex.labels.len()];
        if let Some(zrs) = self.records.get(relative_domain) {
            let mut rrs = Vec::new();
            match qtype {
                QueryType::Wildcard => {
                    for entries in zrs.values() {
                        for entry in entries {
                            if entry.rclass.matches(&qclass) {
                                rrs.push(entry.to_rr(name));
                            }
                        }
                    }
                }
                QueryType::Record(ty) => {
                    if let Some(entries) = zrs.get(&ty) {
                        for entry in entries {
                            if entry.rclass.matches(&qclass) {
                                rrs.push(entry.to_rr(name));
                            }
                        }
                    }
                }
                _ => (),
            }
            Some(rrs)
        } else {
            None
        }
    }

    /// Insert a record for a domain.  This domain MUST be a subdomain
    /// of the apex.
    ///
    /// Note that, for authoritative zones, the SOA `minimum` field is
    /// a lower bound on the TTL of any RR in the zone.  So if this
    /// TTL is lower, it will be raised.
    pub fn insert(
        &mut self,
        name: &DomainName,
        rtype_with_data: RecordTypeWithData,
        rclass: RecordClass,
        ttl: u32,
    ) {
        if !name.is_subdomain_of(&self.apex) {
            return;
        }

        let relative_domain = &name.labels[0..name.labels.len() - self.apex.labels.len()];
        self.records.insert(
            relative_domain,
            rtype_with_data,
            rclass,
            self.actual_ttl(ttl),
        );
    }

    /// Insert a wildcard record for a domain.  This domain MUST be a
    /// subdomain of the apex.
    ///
    /// Note that, for authoritative zones, the SOA `minimum` field is
    /// a lower bound on the TTL of any RR in the zone.  So if this
    /// TTL is lower, it will be raised.
    pub fn insert_wildcard(
        &mut self,
        name: &DomainName,
        rtype_with_data: RecordTypeWithData,
        rclass: RecordClass,
        ttl: u32,
    ) {
        if !name.is_subdomain_of(&self.apex) {
            return;
        }

        let relative_domain = &name.labels[0..name.labels.len() - self.apex.labels.len()];
        self.records.insert_wildcard(
            relative_domain,
            rtype_with_data,
            rclass,
            self.actual_ttl(ttl),
        );
    }

    /// If this zone is authoritative, and the given TTL is below the
    /// SOA `minimum` field, returns the SOA `minimum` field.
    ///
    /// Otherwise returns the given TTL.
    pub fn actual_ttl(&self, ttl: u32) -> u32 {
        if let Some(soa) = &self.soa {
            std::cmp::max(soa.minimum, ttl)
        } else {
            ttl
        }
    }
}

/// The tree of records in a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRecords {
    /// Records for this domain only.
    this: HashMap<RecordType, Vec<ZoneRecord>>,

    /// Wildcard records for subdomains of this which are not in the
    /// `children` map.
    wildcards: Option<HashMap<RecordType, Vec<ZoneRecord>>>,

    /// Child domains, with their own records.
    children: HashMap<Vec<u8>, ZoneRecords>,
}

impl Default for ZoneRecords {
    fn default() -> Self {
        Self::new()
    }
}

impl ZoneRecords {
    pub fn new() -> Self {
        Self {
            this: HashMap::new(),
            wildcards: None,
            children: HashMap::new(),
        }
    }

    /// Follow a relative domain down the tree.
    pub fn get(
        &self,
        relative_domain: &[Vec<u8>],
    ) -> Option<&HashMap<RecordType, Vec<ZoneRecord>>> {
        if relative_domain.is_empty() {
            Some(&self.this)
        } else if let Some(child) = self
            .children
            .get(&relative_domain[relative_domain.len() - 1])
        {
            child.get(&relative_domain[0..relative_domain.len() - 1])
        } else {
            self.wildcards.as_ref()
        }
    }

    /// Add a record.  This will create children as needed.
    pub fn insert(
        &mut self,
        relative_domain: &[Vec<u8>],
        rtype_with_data: RecordTypeWithData,
        rclass: RecordClass,
        ttl: u32,
    ) {
        if relative_domain.is_empty() {
            let rtype = rtype_with_data.rtype();
            let new = ZoneRecord {
                rtype_with_data,
                rclass,
                ttl,
            };
            if let Some(entries) = self.this.get_mut(&rtype) {
                if entries.iter().any(|e| e == &new) {
                    return;
                }

                entries.push(new);
            } else {
                self.this.insert(rtype, vec![new]);
            }
        } else {
            let label = relative_domain[relative_domain.len() - 1].clone();
            let remainder = &relative_domain[0..relative_domain.len() - 1];
            if let Some(child) = self.children.get_mut(&label) {
                child.insert(remainder, rtype_with_data, rclass, ttl);
            } else {
                let mut child = ZoneRecords::new();
                child.insert(remainder, rtype_with_data, rclass, ttl);
                self.children.insert(label, child);
            }
        }
    }

    /// Add a wildcard record.  This will create children as needed.
    pub fn insert_wildcard(
        &mut self,
        relative_domain: &[Vec<u8>],
        rtype_with_data: RecordTypeWithData,
        rclass: RecordClass,
        ttl: u32,
    ) {
        if relative_domain.is_empty() {
            let rtype = rtype_with_data.rtype();
            let new = ZoneRecord {
                rtype_with_data,
                rclass,
                ttl,
            };
            match &mut self.wildcards {
                Some(wildcards) => {
                    if let Some(entries) = wildcards.get_mut(&rtype) {
                        if entries.iter().any(|e| e == &new) {
                            return;
                        }

                        entries.push(new);
                    } else {
                        wildcards.insert(rtype, vec![new]);
                    }
                }
                None => {
                    let mut wildcards = HashMap::new();
                    wildcards.insert(rtype, vec![new]);
                    self.wildcards = Some(wildcards);
                }
            }
        } else {
            let label = relative_domain[relative_domain.len() - 1].clone();
            let remainder = &relative_domain[0..relative_domain.len() - 1];
            if let Some(child) = self.children.get_mut(&label) {
                child.insert_wildcard(remainder, rtype_with_data, rclass, ttl);
            } else {
                let mut child = ZoneRecords::new();
                child.insert_wildcard(remainder, rtype_with_data, rclass, ttl);
                self.children.insert(label, child);
            }
        }
    }
}

/// A SOA record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SOA {
    pub mname: DomainName,
    pub rname: DomainName,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

impl SOA {
    /// Convert it into a SOA RR
    pub fn to_rr(&self, name: &DomainName) -> ResourceRecord {
        ResourceRecord {
            name: name.clone(),
            rtype_with_data: RecordTypeWithData::SOA {
                mname: self.mname.clone(),
                rname: self.rname.clone(),
                serial: self.serial,
                refresh: self.refresh,
                retry: self.retry,
                expire: self.expire,
                minimum: self.minimum,
            },
            rclass: RecordClass::IN,
            ttl: self.minimum,
        }
    }
}

/// A single record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRecord {
    rtype_with_data: RecordTypeWithData,
    rclass: RecordClass,
    ttl: u32,
}

impl ZoneRecord {
    /// Convert it into an RR
    pub fn to_rr(&self, name: &DomainName) -> ResourceRecord {
        ResourceRecord {
            name: name.clone(),
            rtype_with_data: self.rtype_with_data.clone(),
            rclass: self.rclass,
            ttl: self.ttl,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::protocol::wire_types::test_util::*;

    #[test]
    fn zones_build_get_get() {
        let apex = domain("example.com");
        let subdomain = "foo.bar.baz.example.com";
        let a_rr = a_record(subdomain, Ipv4Addr::new(1, 1, 1, 1));
        let ns_rr = ns_record(subdomain, "ns1.example.com");

        let mut zone = Zone::new(apex, None);
        zone.insert(
            &a_rr.name,
            a_rr.rtype_with_data.clone(),
            a_rr.rclass,
            a_rr.ttl,
        );
        zone.insert(
            &ns_rr.name,
            ns_rr.rtype_with_data.clone(),
            ns_rr.rclass,
            ns_rr.ttl,
        );

        let mut zones = Zones::new();
        zones.insert(zone.clone());

        assert_eq!(None, zones.get(&domain("")));
        assert_eq!(None, zones.get(&domain("com")));
        assert_eq!(Some(&zone), zones.get(&domain("example.com")));
        assert_eq!(Some(&zone), zones.get(&domain("www.example.com")));
    }

    #[test]
    fn zone_build_soa() {
        let apex = domain("example.com");
        let soa = SOA {
            mname: domain("mname"),
            rname: domain("rname"),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        };
        let soa_rr = soa.to_rr(&apex);

        let zone = Zone::new(apex.clone(), Some(soa));

        assert_eq!(
            Some(vec![soa_rr]),
            zone.get(&apex, QueryType::Wildcard, QueryClass::Wildcard)
        );
    }

    #[test]
    fn zone_minimum_ttl() {
        let zone = Zone::new(
            domain("example.com"),
            Some(SOA {
                mname: domain("mname"),
                rname: domain("rname"),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 300,
            }),
        );

        assert_eq!(300, zone.actual_ttl(30));
        assert_eq!(301, zone.actual_ttl(301));
    }

    #[test]
    fn zone_build_get() {
        let apex = domain("example.com");
        let subdomain = "foo.bar.baz.example.com";
        let a_rr = a_record(subdomain, Ipv4Addr::new(1, 1, 1, 1));
        let ns_rr = ns_record(subdomain, "ns1.example.com");

        let mut zone = Zone::new(apex, None);
        zone.insert(
            &a_rr.name,
            a_rr.rtype_with_data.clone(),
            a_rr.rclass,
            a_rr.ttl,
        );
        zone.insert(
            &ns_rr.name,
            ns_rr.rtype_with_data.clone(),
            ns_rr.rclass,
            ns_rr.ttl,
        );

        assert_eq!(
            Some(Vec::new()),
            zone.get(
                &domain("example.com"),
                QueryType::Wildcard,
                QueryClass::Wildcard
            )
        );
        assert_eq!(
            Some(Vec::new()),
            zone.get(
                &domain("baz.example.com"),
                QueryType::Wildcard,
                QueryClass::Wildcard
            )
        );
        assert_eq!(
            Some(Vec::new()),
            zone.get(
                &domain("bar.baz.example.com"),
                QueryType::Wildcard,
                QueryClass::Wildcard
            )
        );
        assert_eq!(
            None,
            zone.get(
                &domain("whoops.foo.bar.baz.example.com"),
                QueryType::Wildcard,
                QueryClass::Wildcard
            )
        );

        assert_eq!(
            Some(vec![a_rr.clone()]),
            zone.get(
                &domain(subdomain),
                QueryType::Record(RecordType::A),
                QueryClass::Record(RecordClass::IN),
            )
        );
        assert_eq!(
            Some(vec![a_rr.clone()]),
            zone.get(
                &domain(subdomain),
                QueryType::Record(RecordType::A),
                QueryClass::Wildcard,
            )
        );
        if let Some(mut actual) = zone.get(
            &domain(subdomain),
            QueryType::Wildcard,
            QueryClass::Wildcard,
        ) {
            let mut expected = vec![a_rr, ns_rr];
            expected.sort();
            actual.sort();
            assert_eq!(expected, actual);
        } else {
            panic!("unexpected None");
        }
    }

    #[test]
    fn zrs_insert_get_exact() {
        let mut zrs = ZoneRecords::new();
        let zr_a = a_zonerecord(Ipv4Addr::new(1, 1, 1, 1));
        let zr_ns = ns_zonerecord(domain("ns1.example.net"));

        zrs.insert(
            &domain("www.example.com").labels,
            zr_a.rtype_with_data.clone(),
            zr_a.rclass,
            zr_a.ttl,
        );
        zrs.insert(
            &domain("www.example.com").labels,
            zr_ns.rtype_with_data.clone(),
            zr_ns.rclass,
            zr_ns.ttl,
        );

        let mut zrmap = HashMap::new();
        zrmap.insert(RecordType::A, vec![zr_a]);
        zrmap.insert(RecordType::NS, vec![zr_ns]);

        assert_eq!(Some(&zrmap), zrs.get(&domain("www.example.com").labels));
        assert_eq!(None, zrs.get(&domain("subdomain.www.example.com").labels));
        assert_eq!(None, zrs.get(&domain("sibling.example.com").labels));
        assert_eq!(
            Some(&HashMap::new()),
            zrs.get(&domain("example.com").labels)
        );
        assert_eq!(Some(&HashMap::new()), zrs.get(&domain("com").labels));
    }

    #[test]
    fn zrs_insert_get_wildcard() {
        let mut zrs = ZoneRecords::new();
        let zr_a = a_zonerecord(Ipv4Addr::new(1, 1, 1, 1));
        let zr_ns = ns_zonerecord(domain("ns1.example.net"));

        zrs.insert_wildcard(
            &domain("www.example.com").labels,
            zr_a.rtype_with_data.clone(),
            zr_a.rclass,
            zr_a.ttl,
        );
        zrs.insert_wildcard(
            &domain("www.example.com").labels,
            zr_ns.rtype_with_data.clone(),
            zr_ns.rclass,
            zr_ns.ttl,
        );

        let mut zrmap = HashMap::new();
        zrmap.insert(RecordType::A, vec![zr_a]);
        zrmap.insert(RecordType::NS, vec![zr_ns]);

        assert_eq!(
            Some(&HashMap::new()),
            zrs.get(&domain("www.example.com").labels)
        );
        assert_eq!(
            Some(&zrmap),
            zrs.get(&domain("subdomain.www.example.com").labels)
        );
        assert_eq!(None, zrs.get(&domain("sibling.example.com").labels));
        assert_eq!(
            Some(&HashMap::new()),
            zrs.get(&domain("example.com").labels)
        );
        assert_eq!(Some(&HashMap::new()), zrs.get(&domain("com").labels));
    }

    #[test]
    fn zrs_insert_get_overlap() {
        let mut zrs = ZoneRecords::new();
        let zr_a = a_zonerecord(Ipv4Addr::new(1, 1, 1, 1));
        let zr_ns = ns_zonerecord(domain("ns1.example.net"));

        zrs.insert(
            &domain("www.example.com").labels,
            zr_a.rtype_with_data.clone(),
            zr_a.rclass,
            zr_a.ttl,
        );
        zrs.insert_wildcard(
            &domain("example.com").labels,
            zr_ns.rtype_with_data.clone(),
            zr_ns.rclass,
            zr_ns.ttl,
        );

        let mut zrmap_www = HashMap::new();
        zrmap_www.insert(RecordType::A, vec![zr_a]);
        let mut zrmap_other = HashMap::new();
        zrmap_other.insert(RecordType::NS, vec![zr_ns]);

        assert_eq!(Some(&zrmap_www), zrs.get(&domain("www.example.com").labels));
        assert_eq!(None, zrs.get(&domain("subdomain.www.example.com").labels));
        assert_eq!(
            Some(&zrmap_other),
            zrs.get(&domain("sibling.example.com").labels)
        );
        assert_eq!(
            Some(&HashMap::new()),
            zrs.get(&domain("example.com").labels)
        );
        assert_eq!(Some(&HashMap::new()), zrs.get(&domain("com").labels));
    }

    #[test]
    fn zrs_insert_deduplicates() {
        let mut zrs = ZoneRecords::new();
        let zr_a = a_zonerecord(Ipv4Addr::new(1, 1, 1, 1));

        zrs.insert(
            &domain("www.example.com").labels,
            zr_a.rtype_with_data.clone(),
            zr_a.rclass,
            zr_a.ttl,
        );
        zrs.insert(
            &domain("www.example.com").labels,
            zr_a.rtype_with_data.clone(),
            zr_a.rclass,
            zr_a.ttl,
        );

        let mut zrmap = HashMap::new();
        zrmap.insert(RecordType::A, vec![zr_a]);

        assert_eq!(Some(&zrmap), zrs.get(&domain("www.example.com").labels));
    }

    #[test]
    fn zrs_insert_wildcard_deduplicates() {
        let mut zrs = ZoneRecords::new();
        let zr_a = a_zonerecord(Ipv4Addr::new(1, 1, 1, 1));

        zrs.insert_wildcard(
            &domain("example.com").labels,
            zr_a.rtype_with_data.clone(),
            zr_a.rclass,
            zr_a.ttl,
        );
        zrs.insert_wildcard(
            &domain("example.com").labels,
            zr_a.rtype_with_data.clone(),
            zr_a.rclass,
            zr_a.ttl,
        );

        let mut zrmap = HashMap::new();
        zrmap.insert(RecordType::A, vec![zr_a]);

        assert_eq!(Some(&zrmap), zrs.get(&domain("www.example.com").labels));
    }

    fn a_zonerecord(address: Ipv4Addr) -> ZoneRecord {
        ZoneRecord {
            rtype_with_data: RecordTypeWithData::A { address },
            rclass: RecordClass::IN,
            ttl: 300,
        }
    }

    fn ns_zonerecord(nsdname: DomainName) -> ZoneRecord {
        ZoneRecord {
            rtype_with_data: RecordTypeWithData::NS { nsdname },
            rclass: RecordClass::IN,
            ttl: 300,
        }
    }
}
