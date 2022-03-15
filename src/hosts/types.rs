use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::protocol::types::*;
use crate::zones::types::*;

/// A collection of A records.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
pub struct Hosts {
    pub entries: HashMap<DomainName, Ipv4Addr>,
}

impl Hosts {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Merge another hosts file into this one.  If the same name has
    /// records in both files, the new file will win.
    pub fn merge(&mut self, other: Hosts) {
        for (name, address) in other.entries.into_iter() {
            self.entries.insert(name, address);
        }
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
        for (name, address) in hosts.entries.into_iter() {
            zone.insert(&name, RecordTypeWithData::A { address }, 300);
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

        let mut entries = HashMap::new();
        for (name, zrs) in zone.all_records() {
            for zr in zrs {
                let rr = zr.to_rr(name);
                if let RecordTypeWithData::A { address } = rr.rtype_with_data {
                    entries.insert(rr.name.clone(), address);
                } else {
                    return Err(TryFromZoneError::HasRecordTypesOtherThanA);
                }
            }
        }

        Ok(Self { entries })
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
    use super::test_util::*;
    use super::*;

    #[test]
    fn hosts_zone_roundtrip() {
        let expected = arbitrary_hosts();
        if let Ok(actual) = Hosts::try_from(Zone::from(expected.clone())) {
            assert_eq!(expected, actual);
        } else {
            panic!("expected round-trip");
        }
    }

    #[test]
    fn hosts_merge_zone_merge_equiv() {
        let hosts1 = arbitrary_hosts();
        let hosts2 = arbitrary_hosts();

        let mut combined_hosts = hosts1.clone();
        combined_hosts.merge(hosts2.clone());

        let combined_zone_direct = Zone::from(combined_hosts.clone());
        let mut combined_zone_indirect = Zone::from(hosts1);
        combined_zone_indirect.merge(hosts2.into()).unwrap();

        assert_eq!(combined_zone_direct, combined_zone_indirect);
        assert_eq!(Ok(combined_hosts), combined_zone_direct.try_into());
    }
}

#[cfg(test)]
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
