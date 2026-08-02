use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocol::types::*;
use crate::zones::types::*;

/// TTL used when converting into A / AAAA records.
pub const TTL: u32 = 5;

/// A collection of A records.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
                        v4.insert(rr.name, address);
                    }
                    RecordTypeWithData::AAAA { address } => {
                        v6.insert(rr.name, address);
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

    /// # Errors
    ///
    /// If the zone has wildcard domain names or non-A / non-AAAA
    /// record types.
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
                        v4.insert(rr.name, address);
                    }
                    RecordTypeWithData::AAAA { address } => {
                        v6.insert(rr.name, address);
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
