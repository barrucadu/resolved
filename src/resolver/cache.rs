use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::collections::namespaced_cache::NamespacedCache;
use crate::protocol::wire_types::*;

/// A convenience wrapper around a `Cache` which lets it be shared
/// between threads.
///
/// Invoking `clone` on a `SharedCache` gives a new instance which
/// refers to the same underlying `Cache` object.
#[derive(Debug, Clone)]
pub struct SharedCache {
    #[allow(clippy::type_complexity)]
    cache: Arc<Mutex<NamespacedCache<DomainName, RecordType, (RecordTypeWithData, RecordClass)>>>,
}

const MUTEX_POISON_MESSAGE: &str =
    "[INTERNAL ERROR] cache mutex poisoned, cannot recover from this - aborting";

impl SharedCache {
    /// Make a new, empty, shared cache.
    pub fn new() -> Self {
        SharedCache {
            cache: Arc::new(Mutex::new(NamespacedCache::new())),
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
        let now = Instant::now();
        let records = {
            let mut cache = self.cache.lock().expect(MUTEX_POISON_MESSAGE);
            match qtype {
                QueryType::Wildcard => cache.get_all(now, name),
                QueryType::Record(rtype) => cache.get(now, name, rtype),
                _ => return Vec::new(),
            }
        };
        records
            .into_iter()
            .filter_map(|e| {
                let (rtype_with_data, rclass) = e.value;
                if rclass.matches(qclass) {
                    let ttl = if let Ok(ttl) = e
                        .expires_at
                        .saturating_duration_since(now)
                        .as_secs()
                        .try_into()
                    {
                        ttl
                    } else {
                        u32::MAX
                    };
                    Some(ResourceRecord {
                        name: name.clone(),
                        rtype_with_data,
                        rclass,
                        ttl,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Insert an entry into the cache.
    ///
    /// It is not inserted if its TTL is zero.
    pub fn insert(&self, record: &ResourceRecord) {
        let now = Instant::now();
        if record.ttl > 0 {
            let mut cache = self.cache.lock().expect(MUTEX_POISON_MESSAGE);
            cache.insert(
                now,
                record.name.clone(),
                record.rtype_with_data.rtype(),
                (record.rtype_with_data.clone(), record.rclass),
                now + Duration::from_secs(record.ttl as u64),
            );

            cache.prune(now);
        }
    }

    /// Delete all expired records.
    ///
    /// Returns the number of records deleted.
    pub fn remove_expired(&self) -> usize {
        self.cache
            .lock()
            .expect(MUTEX_POISON_MESSAGE)
            .remove_expired(Instant::now())
    }

    /// Delete all expired records, and then enough
    /// least-recently-used records to reduce the cache to the desired
    /// size.
    ///
    /// Returns the number of records deleted.
    pub fn prune(&self) -> usize {
        self.cache
            .lock()
            .expect(MUTEX_POISON_MESSAGE)
            .prune(Instant::now())
    }
}

impl Default for SharedCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::*;
    use super::*;
    use crate::protocol::wire_types::test_util::*;

    #[test]
    fn cache_put_can_get() {
        for _ in 0..100 {
            let cache = SharedCache::new();
            let mut rr = arbitrary_resourcerecord();
            rr.ttl = 300; // ensure it doesn't expire immediately
            cache.insert(&rr);

            assert_cache_response(
                &rr,
                cache.get(
                    &rr.name,
                    &QueryType::Record(rr.rtype_with_data.rtype()),
                    &QueryClass::Record(rr.rclass),
                ),
            );
            assert_cache_response(
                &rr,
                cache.get(
                    &rr.name,
                    &QueryType::Wildcard,
                    &QueryClass::Record(rr.rclass),
                ),
            );
            assert_cache_response(
                &rr,
                cache.get(
                    &rr.name,
                    &QueryType::Record(rr.rtype_with_data.rtype()),
                    &QueryClass::Wildcard,
                ),
            );
            assert_cache_response(
                &rr,
                cache.get(&rr.name, &QueryType::Wildcard, &QueryClass::Wildcard),
            );
        }
    }
}

#[cfg(test)]
pub mod test_util {
    use super::*;

    /// Assert that the cache response has exactly one element and
    /// that it matches the original (all fields equal except TTL,
    /// where the original is >=).
    pub fn assert_cache_response(original: &ResourceRecord, response: Vec<ResourceRecord>) {
        assert_eq!(1, response.len());
        let cached = response[0].clone();

        assert_eq!(original.name, cached.name);
        assert_eq!(original.rtype_with_data, cached.rtype_with_data);
        assert_eq!(original.rclass, cached.rclass);
        assert!(original.ttl >= cached.ttl);
    }
}
