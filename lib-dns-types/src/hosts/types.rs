use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocol::types::*;
use crate::zones::types::*;

/// TTL used when converting into A / AAAA records.
pub const TTL: u32 = 5;

/// A collection of A records.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(any(feature = "test-util", test), derive(arbitrary::Arbitrary))]
pub struct Hosts {
    pub v4: HashMap<DomainName, Ipv4Addr>,
    pub v6: HashMap<DomainName, Ipv6Addr>,
}

impl Hosts {
    pub fn new() -> Self {
        Self {
            v4: HashMap::new(),
            v6: HashMap::new(),
        }
    }

    /// Merge another hosts file into this one.  If the same name has
    /// records in both files, the new file will win.
    pub fn merge(&mut self, other: Hosts) {
        for (name, address) in other.v4 {
            self.v4.insert(name, address);
        }
        for (name, address) in other.v6 {
            self.v6.insert(name, address);
        }
    }

    /// Convert a zone into a hosts file, discarding any non-A and
    /// non-AAAA records.
    pub fn from_zone_lossy(zone: &Zone) -> Self {
        let mut v4 = HashMap::new();
        let mut v6 = HashMap::new();
        for (name, zrs) in zone.all_records() {
            for zr in zrs {
                let rr = zr.to_rr(name);
                match rr.rtype_with_data {
                    RecordTypeWithData::A { address } => {
                        v4.insert(rr.name.clone(), address);
                    }
                    RecordTypeWithData::AAAA { address } => {
                        v6.insert(rr.name.clone(), address);
                    }
                    _ => (),
                }
            }
        }

        Self { v4, v6 }
    }
}

impl Default for Hosts {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Hosts> for Zone {
    fn from(hosts: Hosts) -> Zone {
        let mut zone = Self::default();
        for (name, address) in hosts.v4 {
            zone.insert(&name, RecordTypeWithData::A { address }, TTL);
        }
        for (name, address) in hosts.v6 {
            zone.insert(&name, RecordTypeWithData::AAAA { address }, TTL);
        }
        zone
    }
}

impl TryFrom<Zone> for Hosts {
    type Error = TryFromZoneError;

    fn try_from(zone: Zone) -> Result<Self, Self::Error> {
        if !zone.all_wildcard_records().is_empty() {
            return Err(TryFromZoneError::HasWildcardRecords);
        }

        let mut v4 = HashMap::new();
        let mut v6 = HashMap::new();
        for (name, zrs) in zone.all_records() {
            for zr in zrs {
                let rr = zr.to_rr(name);
                match rr.rtype_with_data {
                    RecordTypeWithData::A { address } => {
                        v4.insert(rr.name.clone(), address);
                    }
                    RecordTypeWithData::AAAA { address } => {
                        v6.insert(rr.name.clone(), address);
                    }
                    _ => return Err(TryFromZoneError::HasRecordTypesOtherThanA),
                }
            }
        }

        Ok(Self { v4, v6 })
    }
}

/// Errors that can arise when converting a `Zone` into a `Hosts`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum TryFromZoneError {
    HasWildcardRecords,
    HasRecordTypesOtherThanA,
}

#[cfg(test)]
mod tests {
    use crate::protocol::types::test_util::*;

    use super::test_util::*;
    use super::*;

    #[test]
    fn hosts_zone_roundtrip() {
        for _ in 0..100 {
            let expected = arbitrary_hosts();
            if let Ok(actual) = Hosts::try_from(Zone::from(expected.clone())) {
                assert_eq!(expected, actual);
            } else {
                panic!("expected round-trip");
            }
        }
    }

    #[test]
    fn hosts_merge_zone_merge_equiv_when_disjoint() {
        for _ in 0..100 {
            let hosts1 = arbitrary_hosts_with_apex(&domain("hosts1."));
            let hosts2 = arbitrary_hosts_with_apex(&domain("hosts2."));

            let mut combined_hosts = hosts1.clone();
            combined_hosts.merge(hosts2.clone());

            let combined_zone_direct = Zone::from(combined_hosts.clone());
            let mut combined_zone_indirect = Zone::from(hosts1);
            combined_zone_indirect.merge(hosts2.into()).unwrap();

            assert_eq!(combined_zone_direct, combined_zone_indirect);
            assert_eq!(Ok(combined_hosts), combined_zone_direct.try_into());
        }
    }

    fn arbitrary_hosts_with_apex(apex: &DomainName) -> Hosts {
        let arbitrary = arbitrary_hosts();

        let mut out = Hosts::new();
        for (k, v) in arbitrary.v4 {
            let mut k2 = k.clone();
            k2.labels.pop();
            k2.octets.pop();
            k2.labels.append(&mut apex.labels.clone());
            k2.octets.append(&mut apex.octets.clone());
            out.v4.insert(k2, v);
        }
        for (k, v) in arbitrary.v6 {
            let mut k2 = k.clone();
            k2.labels.pop();
            k2.octets.pop();
            k2.labels.append(&mut apex.labels.clone());
            k2.octets.append(&mut apex.octets.clone());
            out.v6.insert(k2, v);
        }
        out
    }
}

#[cfg(any(feature = "test-util", test))]
pub mod test_util {
    use super::*;

    use arbitrary::{Arbitrary, Unstructured};
    use fake::{Fake, Faker};

    pub fn arbitrary_hosts() -> Hosts {
        for size in [128, 256, 512, 1024, 2048, 4096] {
            let mut buf = Vec::new();
            for _ in 0..size {
                buf.push(Faker.fake());
            }

            if let Ok(rr) = Hosts::arbitrary(&mut Unstructured::new(&buf)) {
                return rr;
            }
        }

        panic!("could not generate arbitrary value!");
    }
}
