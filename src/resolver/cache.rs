use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::protocol::{
    DomainName, QueryClass, QueryType, RecordClass, RecordTypeWithData, ResourceRecord,
};

/// A convenience wrapper around a `Cache` which lets it be shared
/// between threads.
///
/// Invoking `clone` on a `SharedCache` gives a new instance which
/// refers to the same underlying `Cache` object.
#[derive(Debug, Clone)]
pub struct SharedCache {
    pub cache: Arc<RwLock<Cache>>,
}

// TODO: evaluate use of unwrap in these methods
impl SharedCache {
    /// Make a new, empty, shared cache.
    pub fn new() -> Self {
        SharedCache {
            cache: Arc::new(RwLock::new(Cache::new())),
        }
    }

    /// Get an entry from the cache.
    ///
    /// The TTL in the returned `ResourceRecord` is relative to the
    /// current time - not when the record was inserted into the
    /// cache.
    pub fn get(
        &self,
        name: &DomainName,
        qtype: &QueryType,
        qclass: &QueryClass,
    ) -> Vec<ResourceRecord> {
        let rrs = self.get_without_checking_expiration(name, qtype, qclass);
        let mut unexpired_rrs = Vec::with_capacity(rrs.len());
        for rr in &rrs {
            if rr.ttl > 0 {
                unexpired_rrs.push(rr.clone());
            }
        }
        if rrs.len() != unexpired_rrs.len() {
            self.remove_expired(name);
        }
        unexpired_rrs
    }

    /// Like `get`, but may return expired entries.
    ///
    /// Consumers MUST check that the TTL of a record is nonzero
    /// before using it!
    pub fn get_without_checking_expiration(
        &self,
        name: &DomainName,
        qtype: &QueryType,
        qclass: &QueryClass,
    ) -> Vec<ResourceRecord> {
        self.cache
            .read()
            .unwrap()
            .get_without_checking_expiration(name, qtype, qclass)
    }

    /// Insert an entry into the cache.
    ///
    /// It is not inserted if its TTL is zero.
    pub fn insert(&self, record: &ResourceRecord) {
        if record.ttl > 0 {
            self.cache.write().unwrap().insert(record)
        }
    }

    /// Delete expired entries for the name.
    pub fn remove_expired(&self, name: &DomainName) {
        self.cache.write().unwrap().remove_expired(name)
    }
}

impl Default for SharedCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Caching for `ResourceRecord`s.
///
/// This is very simple for now: just a `HashMap` of names to
/// expiration times and records, with no maximum size.
///
/// You probably want to use `SharedCache` instead.
///
/// TODO: implement a maximum size, with eviction of
/// least-recently-used entries.
///
/// TODO: use a more efficient data structure, like a trie.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Cache {
    entries: HashMap<DomainName, Vec<(RecordTypeWithData, RecordClass, Instant)>>,
}

impl Cache {
    /// Make a new, empty, cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Get an entry from the cache.
    ///
    /// The TTL in the returned `ResourceRecord` is relative to the
    /// current time - not when the record was inserted into the
    /// cache.
    ///
    /// This entry may have expired: if so, the TTL will be 0.
    /// Consumers MUST check this before using the record!
    pub fn get_without_checking_expiration(
        &self,
        name: &DomainName,
        qtype: &QueryType,
        qclass: &QueryClass,
    ) -> Vec<ResourceRecord> {
        let now = Instant::now();
        if let Some(entries) = self.entries.get(name) {
            let mut rrs = Vec::with_capacity(entries.len());
            for (rtype, rclass, expires) in entries {
                if rtype.matches(qtype) && rclass.matches(qclass) {
                    rrs.push(ResourceRecord {
                        name: name.clone(),
                        rtype_with_data: rtype.clone(),
                        rclass: *rclass,
                        // TODO: remove use of unwrap
                        ttl: expires
                            .saturating_duration_since(now)
                            .as_secs()
                            .try_into()
                            .unwrap(),
                    });
                }
            }
            rrs
        } else {
            Vec::new()
        }
    }

    /// Insert an entry into the cache.
    pub fn insert(&mut self, record: &ResourceRecord) {
        let entry = (
            record.rtype_with_data.clone(),
            record.rclass,
            Instant::now() + Duration::from_secs(record.ttl.into()),
        );
        if let Some(entries) = self.entries.get_mut(&record.name) {
            // TODO: handle duplicate entries
            entries.push(entry);
        } else {
            self.entries.insert(record.name.clone(), vec![entry]);
        }
    }

    /// Delete expired entries for the name.
    pub fn remove_expired(&mut self, name: &DomainName) {
        let now = Instant::now();
        if let Some(entries) = self.entries.get(name) {
            let mut unexpired_entries = Vec::with_capacity(entries.len());
            for (rtype, rclass, expires) in entries {
                if *expires > now {
                    unexpired_entries.push((rtype.clone(), *rclass, *expires));
                }
            }
            if unexpired_entries.is_empty() {
                self.entries.remove(name);
            } else if entries.len() != unexpired_entries.len() {
                self.entries.insert(name.clone(), unexpired_entries);
            }
        }
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}
