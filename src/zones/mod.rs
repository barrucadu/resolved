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
        let mut records = ZoneRecords::new(apex.clone());
        if let Some(soa) = &soa {
            let rr = soa.to_rr(&apex);
            records.insert(&[], rr.rtype_with_data, rr.ttl);
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

    /// Resolve a query.  Returns `None` if the domain is not a
    /// subdomain of the apex.
    ///
    /// This corresponds to step 3 of the standard nameserver
    /// algorithm (see section 4.3.2 of RFC 1034).
    pub fn resolve(&self, name: &DomainName, qtype: QueryType) -> Option<ZoneResult> {
        self.relative_domain(name)
            .map(|relative| self.records.resolve(name, qtype, relative))
    }

    /// Insert a record for a domain.  This domain MUST be a subdomain
    /// of the apex.
    ///
    /// Note that, for authoritative zones, the SOA `minimum` field is
    /// a lower bound on the TTL of any RR in the zone.  So if this
    /// TTL is lower, it will be raised.
    pub fn insert(&mut self, name: &DomainName, rtype_with_data: RecordTypeWithData, ttl: u32) {
        if let Some(relative_domain) = self.relative_domain(name) {
            self.records
                .insert(relative_domain, rtype_with_data, self.actual_ttl(ttl));
        }
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
        ttl: u32,
    ) {
        if let Some(relative_domain) = self.relative_domain(name) {
            self.records
                .insert_wildcard(relative_domain, rtype_with_data, self.actual_ttl(ttl));
        }
    }

    /// Take a domain and chop off the suffix corresponding to the
    /// apex of this zone.
    ///
    /// Returns `None` if the given domain does not match the apex.
    pub fn relative_domain<'a>(&self, name: &'a DomainName) -> Option<&'a [Vec<u8>]> {
        if name.is_subdomain_of(&self.apex) {
            Some(&name.labels[0..name.labels.len() - self.apex.labels.len()])
        } else {
            None
        }
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

/// The result of looking up a name in a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneResult {
    Answer { rrs: Vec<ResourceRecord> },
    CNAME { cname_rr: ResourceRecord },
    Delegation { ns_rrs: Vec<ResourceRecord> },
    NameError,
}

/// The tree of records in a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ZoneRecords {
    /// Fully expanded domain name (labels + apex) of this part of the
    /// tree.  For reconstructing NS RRs from ZRs.
    nsdname: DomainName,

    /// Records for this domain only.
    this: HashMap<RecordType, Vec<ZoneRecord>>,

    /// Wildcard records for subdomains of this which are not in the
    /// `children` map.
    wildcards: Option<HashMap<RecordType, Vec<ZoneRecord>>>,

    /// Child domains, with their own records.
    children: HashMap<Vec<u8>, ZoneRecords>,
}

impl ZoneRecords {
    pub fn new(nsdname: DomainName) -> Self {
        Self {
            nsdname,
            this: HashMap::new(),
            wildcards: None,
            children: HashMap::new(),
        }
    }

    /// Resolve a query
    pub fn resolve(
        &self,
        name: &DomainName,
        qtype: QueryType,
        relative_domain: &[Vec<u8>],
    ) -> ZoneResult {
        if relative_domain.is_empty() {
            // Name matched entirely - this is either case 3.b (if
            // this name is delegated elsewhere) or 3.a (if not) of
            // the standard nameserver algorithm
            zone_result_helper(name, qtype, &self.this, &self.nsdname)
        } else {
            let pos = relative_domain.len() - 1;
            if let Some(child) = self.children.get(&relative_domain[pos]) {
                child.resolve(name, qtype, &relative_domain[0..pos])
            } else if let Some(wildcards) = &self.wildcards {
                // Name cannot be matched further, but there are
                // wildcards.  This is part of case 3.c of the standard
                // nameserver algorithm.
                //
                // Semantics of wildcard NS records are "undefined"
                // and the practice is "discouraged, but not barred"
                // (RFC 4592).  So I've chosen to implement them as
                // prepending the next label to the current name.
                let mut labels = self.nsdname.labels.clone();
                labels.insert(0, relative_domain[pos].clone());
                let nsdname = DomainName::from_labels(labels).unwrap();
                zone_result_helper(name, qtype, wildcards, &nsdname)
            } else {
                // Name cannot be matched further, and there are no
                // wildcards.  Check if there are NS records here: if
                // so, we can delegate (part 3.b of the standard
                // nameserver algorithm), otherwise this is the other
                // part of case 3.c.
                match self.this.get(&RecordType::NS) {
                    Some(ns_zrs) => {
                        if ns_zrs.is_empty() {
                            ZoneResult::NameError
                        } else {
                            ZoneResult::Delegation {
                                ns_rrs: ns_zrs.iter().map(|zr| zr.to_rr(&self.nsdname)).collect(),
                            }
                        }
                    }
                    None => ZoneResult::NameError,
                }
            }
        }
    }

    /// Add a record.  This will create children as needed.
    pub fn insert(
        &mut self,
        relative_domain: &[Vec<u8>],
        rtype_with_data: RecordTypeWithData,
        ttl: u32,
    ) {
        if relative_domain.is_empty() {
            let rtype = rtype_with_data.rtype();
            let new = ZoneRecord {
                rtype_with_data,
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
                child.insert(remainder, rtype_with_data, ttl);
            } else {
                let mut labels = self.nsdname.labels.clone();
                labels.insert(0, label.clone());

                let mut child = ZoneRecords::new(DomainName::from_labels(labels).unwrap());
                child.insert(remainder, rtype_with_data, ttl);
                self.children.insert(label, child);
            }
        }
    }

    /// Add a wildcard record.  This will create children as needed.
    pub fn insert_wildcard(
        &mut self,
        relative_domain: &[Vec<u8>],
        rtype_with_data: RecordTypeWithData,
        ttl: u32,
    ) {
        if relative_domain.is_empty() {
            let rtype = rtype_with_data.rtype();
            let new = ZoneRecord {
                rtype_with_data,
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
                child.insert_wildcard(remainder, rtype_with_data, ttl);
            } else {
                let mut labels = self.nsdname.labels.clone();
                labels.insert(0, label.clone());

                let mut child = ZoneRecords::new(DomainName::from_labels(labels).unwrap());
                child.insert_wildcard(remainder, rtype_with_data, ttl);
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
    ttl: u32,
}

impl ZoneRecord {
    /// Convert it into an RR
    pub fn to_rr(&self, name: &DomainName) -> ResourceRecord {
        ResourceRecord {
            name: name.clone(),
            rtype_with_data: self.rtype_with_data.clone(),
            rclass: RecordClass::IN,
            ttl: self.ttl,
        }
    }
}

/// Handles the terminal cases of step 3 of the standard nameserver
/// algorithm.  If we're here, we've got a domain and records which
/// are associated with it.  The possible cases are:
///
/// - There are `NS` record(s) delegating this name elsewhere, and the
///   qtype is not *exactly equal to* `NS`.  In which case we should
///   return those.  If this is a top-level non-recursive query they
///   will be returned in the AUTHORITY section.
///
/// - There's a `CNAME` record on this name, and the qtype does *not*
///   match `CNAME`.  In which case we return a `CNAME` response, and
///   the upstream resolver will then try go resolve that.
///
/// - Otherwise, return all RRs which match the query: this answers
///   the question.
fn zone_result_helper(
    name: &DomainName,
    qtype: QueryType,
    records: &HashMap<RecordType, Vec<ZoneRecord>>,
    nsdname: &DomainName,
) -> ZoneResult {
    if QueryType::Record(RecordType::NS) != qtype {
        match records.get(&RecordType::NS) {
            Some(ns_zrs) => {
                if !ns_zrs.is_empty() {
                    return ZoneResult::Delegation {
                        ns_rrs: ns_zrs.iter().map(|zr| zr.to_rr(nsdname)).collect(),
                    };
                }
            }
            None => (),
        }
    }

    if !RecordType::CNAME.matches(&qtype) {
        match records.get(&RecordType::CNAME) {
            Some(cname_zrs) => {
                if !cname_zrs.is_empty() {
                    return ZoneResult::CNAME {
                        cname_rr: cname_zrs[0].to_rr(name),
                    };
                }
            }
            None => (),
        }
    }

    match qtype {
        QueryType::Wildcard => {
            let mut rrs = Vec::new();
            for zrs in records.values() {
                rrs.append(&mut zrs.iter().map(|zr| zr.to_rr(name)).collect());
            }
            ZoneResult::Answer { rrs }
        }
        QueryType::Record(rtype) => ZoneResult::Answer {
            rrs: if let Some(zrs) = records.get(&rtype) {
                zrs.iter().map(|zr| zr.to_rr(name)).collect()
            } else {
                Vec::new()
            },
        },
        _ => ZoneResult::Answer { rrs: Vec::new() },
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
        zone.insert(&a_rr.name, a_rr.rtype_with_data.clone(), a_rr.ttl);
        zone.insert(&ns_rr.name, ns_rr.rtype_with_data.clone(), ns_rr.ttl);

        let mut zones = Zones::new();
        zones.insert(zone.clone());

        assert_eq!(None, zones.get(&domain("")));
        assert_eq!(None, zones.get(&domain("com")));
        assert_eq!(Some(&zone), zones.get(&domain("example.com")));
        assert_eq!(Some(&zone), zones.get(&domain("www.example.com")));
    }

    #[test]
    fn zone_authoritative_minimum_ttl() {
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
    fn zone_nonauthoritative_minimum_ttl() {
        let zone = Zone::new(domain("example.com"), None);

        assert_eq!(30, zone.actual_ttl(30));
        assert_eq!(301, zone.actual_ttl(301));
    }

    #[test]
    fn zone_resolve_soa() {
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
            Some(ZoneResult::Answer { rrs: vec![soa_rr] }),
            zone.resolve(&apex, QueryType::Record(RecordType::SOA))
        );
    }

    #[test]
    fn zone_insert_resolve() {
        for _ in 0..100 {
            let mut zone = Zone::new(domain("example.com"), None);
            let mut rr = arbitrary_resourcerecord();
            rr.rclass = RecordClass::IN;
            make_subdomain(&zone.apex, &mut rr.name);

            zone.insert(&rr.name, rr.rtype_with_data.clone(), rr.ttl);

            let expected = Some(ZoneResult::Answer {
                rrs: vec![rr.clone()],
            });

            assert_eq!(
                expected,
                zone.resolve(&rr.name, QueryType::Record(rr.rtype_with_data.rtype()))
            );
            assert_eq!(expected, zone.resolve(&rr.name, QueryType::Wildcard));
        }
    }

    #[test]
    fn zone_insert_wildcard_resolve() {
        for _ in 0..100 {
            let mut zone = Zone::new(domain("example.com"), None);
            let mut rr = arbitrary_resourcerecord();
            rr.rclass = RecordClass::IN;
            make_subdomain(&zone.apex, &mut rr.name);

            zone.insert_wildcard(&rr.name, rr.rtype_with_data.clone(), rr.ttl);

            let mut subdomain = domain("foo");
            make_subdomain(&rr.name, &mut subdomain);
            rr.name = subdomain;

            let expected = Some(ZoneResult::Answer {
                rrs: vec![rr.clone()],
            });

            assert_eq!(
                expected,
                zone.resolve(&rr.name, QueryType::Record(rr.rtype_with_data.rtype()))
            );
            assert_eq!(expected, zone.resolve(&rr.name, QueryType::Wildcard));
        }
    }

    #[test]
    fn zone_resolve_cname() {
        let mut zone = Zone::new(domain("example.com"), None);
        let rr = cname_record("www.example.com", "example.com");
        zone.insert(&rr.name, rr.rtype_with_data.clone(), rr.ttl);

        assert_eq!(
            Some(ZoneResult::CNAME {
                cname_rr: rr.clone()
            }),
            zone.resolve(&rr.name, QueryType::Record(RecordType::A))
        );
        assert_eq!(
            Some(ZoneResult::Answer {
                rrs: vec![rr.clone()]
            }),
            zone.resolve(&rr.name, QueryType::Record(RecordType::CNAME))
        );
        assert_eq!(
            Some(ZoneResult::Answer {
                rrs: vec![rr.clone()]
            }),
            zone.resolve(&rr.name, QueryType::Wildcard)
        );
    }

    #[test]
    fn zone_resolve_cname_wildcard() {
        let mut zone = Zone::new(domain("example.com"), None);
        let wildcard_rr = cname_record("example.com", "example.com"); // *.example.com
        let rr = cname_record("www.example.com", "example.com");
        zone.insert_wildcard(
            &wildcard_rr.name,
            wildcard_rr.rtype_with_data.clone(),
            wildcard_rr.ttl,
        );

        assert_eq!(
            Some(ZoneResult::CNAME {
                cname_rr: rr.clone()
            }),
            zone.resolve(&rr.name, QueryType::Record(RecordType::A))
        );
        assert_eq!(
            Some(ZoneResult::Answer {
                rrs: vec![rr.clone()]
            }),
            zone.resolve(&rr.name, QueryType::Record(RecordType::CNAME))
        );
        assert_eq!(
            Some(ZoneResult::Answer {
                rrs: vec![rr.clone()]
            }),
            zone.resolve(&rr.name, QueryType::Wildcard)
        );
    }

    #[test]
    fn zone_resolve_delegation() {
        let mut zone = Zone::new(domain("example.com"), None);
        let rr = ns_record("www.example.com", "ns.example.com");
        zone.insert(&rr.name, rr.rtype_with_data.clone(), rr.ttl);

        assert_eq!(
            Some(ZoneResult::Delegation {
                ns_rrs: vec![rr.clone()]
            }),
            zone.resolve(&rr.name, QueryType::Record(RecordType::A))
        );
        assert_eq!(
            Some(ZoneResult::Answer {
                rrs: vec![rr.clone()]
            }),
            zone.resolve(&rr.name, QueryType::Record(RecordType::NS))
        );
        assert_eq!(
            Some(ZoneResult::Delegation {
                ns_rrs: vec![rr.clone()]
            }),
            zone.resolve(&rr.name, QueryType::Wildcard)
        );
    }

    #[test]
    fn zone_resolve_delegation_wildcard() {
        let mut zone = Zone::new(domain("example.com"), None);
        let wildcard_rr = ns_record("example.com", "ns.example.com");
        let rr = ns_record("www.example.com", "ns.example.com");
        zone.insert_wildcard(
            &wildcard_rr.name,
            wildcard_rr.rtype_with_data.clone(),
            wildcard_rr.ttl,
        );

        assert_eq!(
            Some(ZoneResult::Delegation {
                ns_rrs: vec![rr.clone()]
            }),
            zone.resolve(&rr.name, QueryType::Record(RecordType::A))
        );
        assert_eq!(
            Some(ZoneResult::Answer {
                rrs: vec![rr.clone()]
            }),
            zone.resolve(&rr.name, QueryType::Record(RecordType::NS))
        );
        assert_eq!(
            Some(ZoneResult::Delegation {
                ns_rrs: vec![rr.clone()]
            }),
            zone.resolve(&rr.name, QueryType::Wildcard)
        );
    }

    #[test]
    fn zone_resolve_delegation_wildcard_multilabel() {
        let mut zone = Zone::new(domain("example.com"), None);
        let wildcard_rr = ns_record("example.com", "ns.example.com");
        zone.insert_wildcard(
            &wildcard_rr.name,
            wildcard_rr.rtype_with_data.clone(),
            wildcard_rr.ttl,
        );

        assert_eq!(
            Some(ZoneResult::Delegation {
                ns_rrs: vec![ns_record("www.example.com", "ns.example.com")]
            }),
            zone.resolve(
                &domain("some.long.subdomain.of.www.example.com"),
                QueryType::Record(RecordType::A),
            )
        );
    }

    #[test]
    fn zone_resolve_nameerror() {
        let mut zone = Zone::new(domain("example.com"), None);
        let rr = a_record("www.example.com", Ipv4Addr::new(1, 1, 1, 1));
        zone.insert(&rr.name, rr.rtype_with_data, rr.ttl);

        assert_eq!(
            Some(ZoneResult::NameError),
            zone.resolve(&domain("subdomain.www.example.com"), QueryType::Wildcard)
        );
        assert_eq!(
            Some(ZoneResult::NameError),
            zone.resolve(&domain("sibling.example.com"), QueryType::Wildcard)
        );
    }

    #[test]
    fn zone_resolve_empty_answer_not_nameerror_for_subdomain() {
        let mut zone = Zone::new(domain("example.com"), None);
        let rr = a_record(
            "long.chain.of.subdomains.example.com",
            Ipv4Addr::new(1, 1, 1, 1),
        );
        zone.insert(&rr.name, rr.rtype_with_data, rr.ttl);

        assert_eq!(
            Some(ZoneResult::Answer { rrs: Vec::new() }),
            zone.resolve(
                &domain("chain.of.subdomains.example.com"),
                QueryType::Wildcard,
            )
        );
        assert_eq!(
            Some(ZoneResult::Answer { rrs: Vec::new() }),
            zone.resolve(&domain("of.subdomains.example.com"), QueryType::Wildcard)
        );
        assert_eq!(
            Some(ZoneResult::Answer { rrs: Vec::new() }),
            zone.resolve(&domain("subdomains.example.com"), QueryType::Wildcard)
        );
        assert_eq!(
            Some(ZoneResult::Answer { rrs: Vec::new() }),
            zone.resolve(&domain("example.com"), QueryType::Wildcard)
        );
    }

    fn make_subdomain(apex: &DomainName, domain: &mut DomainName) {
        domain.labels.pop();
        domain.octets.pop();
        domain.labels.append(&mut apex.labels.clone());
        domain.octets.append(&mut apex.octets.clone());
    }
}
