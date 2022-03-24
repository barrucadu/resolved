use priority_queue::PriorityQueue;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dns_types::protocol::types::*;

/// A convenience wrapper around a `Cache` which lets it be shared
/// between threads.
///
/// Invoking `clone` on a `SharedCache` gives a new instance which
/// refers to the same underlying `Cache` object.
#[derive(Debug, Clone)]
pub struct SharedCache {
    cache: Arc<Mutex<Cache>>,
}

const MUTEX_POISON_MESSAGE: &str =
    "[INTERNAL ERROR] cache mutex poisoned, cannot recover from this - aborting";

impl SharedCache {
    /// Make a new, empty, shared cache.
    pub fn new() -> Self {
        SharedCache {
            cache: Arc::new(Mutex::new(Cache::new())),
        }
    }

    /// Create a new cache with the given desired size.
    pub fn with_desired_size(desired_size: usize) -> Self {
        SharedCache {
            cache: Arc::new(Mutex::new(Cache::with_desired_size(desired_size))),
        }
    }

    /// Get an entry from the cache.
    ///
    /// The TTL in the returned `ResourceRecord` is relative to the
    /// current time - not when the record was inserted into the
    /// cache.
    pub fn get(&self, name: &DomainName, qtype: &QueryType) -> Vec<ResourceRecord> {
        let mut rrs = self.get_without_checking_expiration(name, qtype);
        rrs.retain(|rr| rr.ttl > 0);
        rrs
    }

    /// Like `get`, but may return expired entries.
    ///
    /// Consumers MUST check that the TTL of a record is nonzero
    /// before using it!
    pub fn get_without_checking_expiration(
        &self,
        name: &DomainName,
        qtype: &QueryType,
    ) -> Vec<ResourceRecord> {
        self.cache
            .lock()
            .expect(MUTEX_POISON_MESSAGE)
            .get_without_checking_expiration(name, qtype)
    }

    /// Insert an entry into the cache.
    ///
    /// It is not inserted if its TTL is zero.
    ///
    /// This may make the cache grow beyond the desired size.
    pub fn insert(&self, record: &ResourceRecord) {
        if record.ttl > 0 {
            let mut cache = self.cache.lock().expect(MUTEX_POISON_MESSAGE);
            cache.insert(record);
        }
    }

    /// Atomically clears expired entries and, if the cache has grown
    /// beyond its desired size, prunes entries to get down to size.
    ///
    /// Returns `(has overflowed?, current size, num expired, num pruned)`.
    pub fn prune(&self) -> (bool, usize, usize, usize) {
        self.cache.lock().expect(MUTEX_POISON_MESSAGE).prune()
    }
}

impl Default for SharedCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Caching for `ResourceRecord`s.
///
/// You probably want to use `SharedCache` instead.
#[derive(Debug, Clone)]
pub struct Cache {
    /// Cached records, indexed by domain name.
    ///
    /// TODO: see if some other structure, like a trie using the name
    /// labels, would be better here.
    entries: HashMap<DomainName, CachedDomainRecords>,

    /// Priority queue of domain names ordered by access times.
    ///
    /// When the cache is full and there are no expired records to
    /// prune, domains will instead be pruned in LRU order.
    ///
    /// INVARIANT: the domains in here are exactly the domains in
    /// `entries`.
    access_priority: PriorityQueue<DomainName, Reverse<Instant>>,

    /// Priority queue of domain names ordered by expiry time.
    ///
    /// When the cache is pruned, expired records are removed first.
    ///
    /// INVARIANT: the domains in here are exactly the domains in
    /// `entries`.
    expiry_priority: PriorityQueue<DomainName, Reverse<Instant>>,

    /// The number of records in the cache.
    ///
    /// INVARIANT: this is the sum of the `size` fields of the
    /// entries.
    current_size: usize,

    /// The desired maximum number of records in the cache.
    desired_size: usize,
}

/// The cached records for a domain.
#[derive(Debug, Clone, Eq, PartialEq)]
struct CachedDomainRecords {
    /// The time this record was last read at.
    last_read: Instant,

    /// When the next RR expires.
    ///
    /// INVARIANT: this is the minimum of the expiry times of the RRs.
    next_expiry: Instant,

    /// How many records there are.
    ///
    /// INVARIANT: this is the sum of the vector lengths in `records`.
    size: usize,

    /// The records, further divided by record type.
    ///
    /// INVARIANT: the `RecordType` and `RecordTypeWithData` match.
    records: HashMap<RecordType, Vec<(RecordTypeWithData, Instant)>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    /// Create a new cache with a default desired size.
    pub fn new() -> Self {
        Self::with_desired_size(512)
    }

    /// Create a new cache with the given desired size.
    ///
    /// If the number of entries exceeds this, expired and
    /// least-recently-used items will be pruned.
    ///
    /// Panics:
    ///
    /// - If called with a desired_size of 0.
    pub fn with_desired_size(desired_size: usize) -> Self {
        if desired_size == 0 {
            panic!("cannot create a zero-size cache");
        }

        Self {
            // `desired_size / 2` is a compromise: most domains will
            // have more than one record, so `desired_size` would be
            // too big for the `entries`.
            entries: HashMap::with_capacity(desired_size / 2),
            access_priority: PriorityQueue::with_capacity(desired_size),
            expiry_priority: PriorityQueue::with_capacity(desired_size),
            current_size: 0,
            desired_size,
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
        &mut self,
        name: &DomainName,
        qtype: &QueryType,
    ) -> Vec<ResourceRecord> {
        if let Some(entry) = self.entries.get_mut(name) {
            let now = Instant::now();
            let mut rrs = Vec::new();
            match qtype {
                QueryType::Wildcard => {
                    for tuples in entry.records.values() {
                        to_rrs(name, now, tuples, &mut rrs);
                    }
                }
                QueryType::Record(rtype) => {
                    if let Some(tuples) = entry.records.get(rtype) {
                        to_rrs(name, now, tuples, &mut rrs);
                    }
                }
                _ => (),
            }
            if !rrs.is_empty() {
                entry.last_read = now;
                self.access_priority
                    .change_priority(name, Reverse(entry.last_read));
            }
            rrs
        } else {
            Vec::new()
        }
    }

    /// Insert an entry into the cache.
    pub fn insert(&mut self, record: &ResourceRecord) {
        let now = Instant::now();
        let rtype = record.rtype_with_data.rtype();
        let expiry = Instant::now() + Duration::from_secs(record.ttl.into());
        let tuple = (record.rtype_with_data.clone(), expiry);
        if let Some(entry) = self.entries.get_mut(&record.name) {
            if let Some(tuples) = entry.records.get_mut(&rtype) {
                let mut duplicate_expires_at = None;
                for i in 0..tuples.len() {
                    let t = &tuples[i];
                    if t.0 == tuple.0 {
                        duplicate_expires_at = Some(t.1);
                        tuples.swap_remove(i);
                        break;
                    }
                }

                tuples.push(tuple);

                if let Some(dup_expiry) = duplicate_expires_at {
                    entry.size -= 1;
                    self.current_size -= 1;

                    if dup_expiry == entry.next_expiry {
                        let mut new_next_expiry = expiry;
                        for (_, e) in tuples {
                            if *e < new_next_expiry {
                                new_next_expiry = *e;
                            }
                        }
                        entry.next_expiry = new_next_expiry;
                        self.expiry_priority
                            .change_priority(&record.name, Reverse(entry.next_expiry));
                    }
                }
            } else {
                entry.records.insert(rtype, vec![tuple]);
            }
            entry.last_read = now;
            entry.size += 1;
            self.access_priority
                .change_priority(&record.name, Reverse(entry.last_read));
            if expiry < entry.next_expiry {
                entry.next_expiry = expiry;
                self.expiry_priority
                    .change_priority(&record.name, Reverse(entry.next_expiry));
            }
        } else {
            let mut records = HashMap::new();
            records.insert(rtype, vec![tuple]);
            let entry = CachedDomainRecords {
                last_read: now,
                next_expiry: expiry,
                size: 1,
                records,
            };
            self.access_priority
                .push(record.name.clone(), Reverse(entry.last_read));
            self.expiry_priority
                .push(record.name.clone(), Reverse(entry.next_expiry));
            self.entries.insert(record.name.clone(), entry);
        }

        self.current_size += 1;
    }

    /// Delete all expired records.
    ///
    /// Returns the number of records deleted.
    pub fn remove_expired(&mut self) -> usize {
        let mut pruned = 0;

        loop {
            let before = pruned;
            pruned += self.remove_expired_step();
            if before == pruned {
                break;
            }
        }

        pruned
    }

    /// Delete all expired records, and then enough
    /// least-recently-used records to reduce the cache to the desired
    /// size.
    ///
    /// Returns `(has overflowed?, current size, num expired, num pruned)`.
    pub fn prune(&mut self) -> (bool, usize, usize, usize) {
        let has_overflowed = self.current_size > self.desired_size;
        let num_expired = self.remove_expired();
        let mut num_pruned = 0;

        while self.current_size > self.desired_size {
            num_pruned += self.remove_least_recently_used();
        }

        (has_overflowed, self.current_size, num_expired, num_pruned)
    }

    /// Helper for `remove_expired`: looks at the next-to-expire
    /// domain and cleans up expired records from it.  This may delete
    /// more than one record, and may even delete the whole domain.
    ///
    /// Returns the number of records removed.
    fn remove_expired_step(&mut self) -> usize {
        if let Some((name, Reverse(expiry))) = self.expiry_priority.pop() {
            let now = Instant::now();

            if expiry > now {
                self.expiry_priority.push(name, Reverse(expiry));
                return 0;
            }

            if let Some(entry) = self.entries.get_mut(&name) {
                let mut pruned = 0;

                let rtypes = entry.records.keys().cloned().collect::<Vec<RecordType>>();
                let mut next_expiry = None;
                for rtype in rtypes {
                    if let Some(tuples) = entry.records.get_mut(&rtype) {
                        let len = tuples.len();
                        tuples.retain(|(_, expiry)| expiry > &now);
                        pruned += len - tuples.len();
                        for (_, expiry) in tuples {
                            match next_expiry {
                                None => next_expiry = Some(*expiry),
                                Some(t) if *expiry < t => next_expiry = Some(*expiry),
                                _ => (),
                            }
                        }
                    }
                }

                entry.size -= pruned;

                if let Some(ne) = next_expiry {
                    entry.next_expiry = ne;
                    self.expiry_priority.push(name, Reverse(ne));
                } else {
                    self.entries.remove(&name);
                    self.access_priority.remove(&name);
                }

                self.current_size -= pruned;
                pruned
            } else {
                self.access_priority.remove(&name);
                0
            }
        } else {
            0
        }
    }

    /// Helper for `prune`: deletes all records associated with the
    /// least recently used domain.
    ///
    /// Returns the number of records removed.
    fn remove_least_recently_used(&mut self) -> usize {
        if let Some((name, _)) = self.access_priority.pop() {
            self.expiry_priority.remove(&name);

            if let Some(entry) = self.entries.remove(&name) {
                let pruned = entry.size;
                self.current_size -= pruned;
                pruned
            } else {
                0
            }
        } else {
            0
        }
    }
}

/// Helper for `get_without_checking_expiration`: converts the cached
/// record tuples into RRs.
fn to_rrs(
    name: &DomainName,
    now: Instant,
    tuples: &[(RecordTypeWithData, Instant)],
    rrs: &mut Vec<ResourceRecord>,
) {
    for (rtype, expires) in tuples {
        let ttl = if let Ok(ttl) = expires.saturating_duration_since(now).as_secs().try_into() {
            ttl
        } else {
            u32::MAX
        };

        rrs.push(ResourceRecord {
            name: name.clone(),
            rtype_with_data: rtype.clone(),
            rclass: RecordClass::IN,
            ttl,
        });
    }
}

#[cfg(test)]
mod tests {
    use dns_types::protocol::types::test_util::*;

    use super::test_util::*;
    use super::*;

    #[test]
    fn cache_put_can_get() {
        for _ in 0..100 {
            let mut cache = Cache::new();
            let mut rr = arbitrary_resourcerecord();
            rr.rclass = RecordClass::IN;
            cache.insert(&rr);

            assert_cache_response(
                &rr,
                cache.get_without_checking_expiration(
                    &rr.name,
                    &QueryType::Record(rr.rtype_with_data.rtype()),
                ),
            );
            assert_cache_response(
                &rr,
                cache.get_without_checking_expiration(&rr.name, &QueryType::Wildcard),
            );
        }
    }

    #[test]
    fn cache_put_deduplicates_and_maintains_invariants() {
        let mut cache = Cache::new();
        let mut rr = arbitrary_resourcerecord();
        rr.rclass = RecordClass::IN;

        cache.insert(&rr);
        cache.insert(&rr);

        assert_eq!(1, cache.current_size);
        assert_invariants(&cache);
    }

    #[test]
    fn cache_put_maintains_invariants() {
        let mut cache = Cache::new();

        for _ in 0..100 {
            let mut rr = arbitrary_resourcerecord();
            rr.rclass = RecordClass::IN;
            cache.insert(&rr);
        }

        assert_invariants(&cache);
    }

    #[test]
    fn cache_put_then_get_maintains_invariants() {
        let mut cache = Cache::new();
        let mut queries = Vec::new();

        for _ in 0..100 {
            let mut rr = arbitrary_resourcerecord();
            rr.rclass = RecordClass::IN;
            cache.insert(&rr);
            queries.push((
                rr.name.clone(),
                QueryType::Record(rr.rtype_with_data.rtype()),
            ));
        }
        for (name, qtype) in queries {
            cache.get_without_checking_expiration(&name, &qtype);
        }

        assert_invariants(&cache);
    }

    #[test]
    fn cache_put_then_prune_maintains_invariants() {
        let mut cache = Cache::with_desired_size(25);

        for _ in 0..100 {
            let mut rr = arbitrary_resourcerecord();
            rr.rclass = RecordClass::IN;
            rr.ttl = 300; // this case isn't testing expiration
            cache.insert(&rr);
        }

        // might be more than 75 because the size is measured in
        // records, but pruning is done on whole domains
        let (overflow, current_size, expired, pruned) = cache.prune();
        assert!(overflow);
        assert_eq!(0, expired);
        assert!(pruned >= 75);
        assert!(cache.current_size <= 25);
        assert_eq!(cache.current_size, current_size);
        assert_invariants(&cache);
    }

    #[test]
    fn cache_put_then_expire_maintains_invariants() {
        let mut cache = Cache::new();

        for i in 0..100 {
            let mut rr = arbitrary_resourcerecord();
            rr.rclass = RecordClass::IN;
            rr.ttl = if i > 0 && i % 2 == 0 { 0 } else { 300 };
            cache.insert(&rr);
        }

        assert_eq!(49, cache.remove_expired());
        assert_eq!(51, cache.current_size);
        assert_invariants(&cache);
    }

    #[test]
    fn cache_prune_expires_all() {
        let mut cache = Cache::with_desired_size(99);

        for i in 0..100 {
            let mut rr = arbitrary_resourcerecord();
            rr.rclass = RecordClass::IN;
            rr.ttl = if i > 0 && i % 2 == 0 { 0 } else { 300 };
            cache.insert(&rr);
        }

        let (overflow, current_size, expired, pruned) = cache.prune();
        assert!(overflow);
        assert_eq!(49, expired);
        assert_eq!(0, pruned);
        assert_eq!(cache.current_size, current_size);
        assert_invariants(&cache);
    }

    fn assert_invariants(cache: &Cache) {
        assert_eq!(
            cache.current_size,
            cache.entries.values().map(|e| e.size).sum::<usize>()
        );

        assert_eq!(cache.entries.len(), cache.access_priority.len());
        assert_eq!(cache.entries.len(), cache.expiry_priority.len());

        let mut access_priority = PriorityQueue::new();
        let mut expiry_priority = PriorityQueue::new();

        for (name, entry) in cache.entries.iter() {
            assert_eq!(
                entry.size,
                entry.records.values().map(|r| r.len()).sum::<usize>()
            );

            let mut min_expires = None;
            for (rtype, tuples) in entry.records.iter() {
                for (rtype_with_data, expires) in tuples {
                    assert_eq!(*rtype, rtype_with_data.rtype());

                    if let Some(e) = min_expires {
                        if *expires < e {
                            min_expires = Some(*expires);
                        }
                    } else {
                        min_expires = Some(*expires);
                    }
                }
            }

            assert_eq!(Some(entry.next_expiry), min_expires);

            access_priority.push(name.clone(), Reverse(entry.last_read));
            expiry_priority.push(name.clone(), Reverse(entry.next_expiry));
        }

        assert_eq!(cache.access_priority, access_priority);
        assert_eq!(cache.expiry_priority, expiry_priority);
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
        assert_eq!(RecordClass::IN, cached.rclass);
        assert!(original.ttl >= cached.ttl);
    }
}
