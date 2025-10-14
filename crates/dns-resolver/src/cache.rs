use priority_queue::PriorityQueue;
use std::cmp::Eq;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::Copy;
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
    ///
    /// # Panics
    ///
    /// If the mutex has been poisoned.
    pub fn get(&self, name: &DomainName, qtype: QueryType) -> Vec<ResourceRecord> {
        self.cache
            .lock()
            .expect(MUTEX_POISON_MESSAGE)
            .get(name, qtype)
    }

    /// Like `get`, but may return expired entries.
    ///
    /// Consumers MUST check that the TTL of a record is nonzero
    /// before using it!
    ///
    /// # Panics
    ///
    /// If the mutex has been poisoned.
    pub fn get_without_checking_expiration(
        &self,
        name: &DomainName,
        qtype: QueryType,
    ) -> Vec<ResourceRecord> {
        self.cache
            .lock()
            .expect(MUTEX_POISON_MESSAGE)
            .get_without_checking_expiration(name, qtype)
    }

    /// Insert an entry into the cache.
    ///
    /// It is not inserted if its TTL is zero or negative.
    ///
    /// This may make the cache grow beyond the desired size.
    ///
    /// # Panics
    ///
    /// If the mutex has been poisoned.
    pub fn insert(&self, record: &ResourceRecord) {
        if record.ttl > 0 {
            let mut cache = self.cache.lock().expect(MUTEX_POISON_MESSAGE);
            cache.insert(record);
        }
    }

    /// Insert multiple entries into the cache.
    ///
    /// This is more efficient than calling `insert` multiple times, as it locks
    /// the cache just once.
    ///
    /// Records with a TTL of zero or negative are skipped.
    ///
    /// This may make the cache grow beyond the desired size.
    ///
    /// # Panics
    ///
    /// If the mutex has been poisoned.
    pub fn insert_all(&self, records: &[ResourceRecord]) {
        let mut cache = self.cache.lock().expect(MUTEX_POISON_MESSAGE);
        for record in records {
            if record.ttl > 0 {
                cache.insert(record);
            }
        }
    }

    /// Atomically clears expired entries and, if the cache has grown
    /// beyond its desired size, prunes entries to get down to size.
    ///
    /// Returns `(has overflowed?, current size, num expired, num pruned)`.
    ///
    /// # Panics
    ///
    /// If the mutex has been poisoned.
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
    inner: PartitionedCache<DomainName, RecordType, RecordTypeWithData>,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    /// Create a new cache with a default desired size.
    pub fn new() -> Self {
        Self {
            inner: PartitionedCache::new(),
        }
    }

    /// Create a new cache with the given desired size.
    ///
    /// The `prune` method will remove expired entries, and also enough entries
    /// (in least-recently-used order) to get down to this size.
    pub fn with_desired_size(desired_size: usize) -> Self {
        Self {
            inner: PartitionedCache::with_desired_size(desired_size),
        }
    }

    /// Get RRs from the cache.
    ///
    /// The TTL in the returned `ResourceRecord` is relative to the
    /// current time - not when the record was inserted into the
    /// cache.
    pub fn get(&mut self, name: &DomainName, qtype: QueryType) -> Vec<ResourceRecord> {
        let mut rrs = self.get_without_checking_expiration(name, qtype);
        rrs.retain(|rr| rr.ttl > 0);
        rrs
    }

    /// Like `get`, but may return expired RRs.
    ///
    /// Consumers MUST check that the TTL of a record is nonzero before using
    /// it!
    pub fn get_without_checking_expiration(
        &mut self,
        name: &DomainName,
        qtype: QueryType,
    ) -> Vec<ResourceRecord> {
        let now = Instant::now();
        let mut rrs = Vec::new();
        match qtype {
            QueryType::Wildcard => {
                if let Some(records) = self.inner.get_partition_without_checking_expiration(name) {
                    for tuples in records.values() {
                        to_rrs(name, now, tuples, &mut rrs);
                    }
                }
            }
            QueryType::Record(rtype) => {
                if let Some(tuples) = self.inner.get_without_checking_expiration(name, &rtype) {
                    to_rrs(name, now, tuples, &mut rrs);
                }
            }
            _ => (),
        }

        rrs
    }

    /// Insert an RR into the cache.
    pub fn insert(&mut self, record: &ResourceRecord) {
        self.inner.upsert(
            record.name.clone(),
            record.rtype_with_data.rtype(),
            record.rtype_with_data.clone(),
            Duration::from_secs(record.ttl.into()),
        );
    }

    /// Clear expired RRs and, if the cache has grown beyond its desired size,
    /// prunes domains to get down to size.
    ///
    /// Returns `(has overflowed?, current size, num expired, num pruned)`.
    pub fn prune(&mut self) -> (bool, usize, usize, usize) {
        self.inner.prune()
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
        rrs.push(ResourceRecord {
            name: name.clone(),
            rtype_with_data: rtype.clone(),
            rclass: RecordClass::IN,
            ttl: expires
                .saturating_duration_since(now)
                .as_secs()
                .try_into()
                .unwrap_or(u32::MAX),
        });
    }
}

#[derive(Debug, Clone)]
pub struct PartitionedCache<K1: Eq + Hash, K2: Eq + Hash, V> {
    /// Cached entries, indexed by partition key.
    partitions: HashMap<K1, Partition<K2, V>>,

    /// Priority queue of partition keys ordered by access times.
    ///
    /// When the cache is full and there are no expired records to prune,
    /// partitions will instead be pruned in LRU order.
    ///
    /// INVARIANT: the keys in here are exactly the keys in `partitions`.
    access_priority: PriorityQueue<K1, Reverse<Instant>>,

    /// Priority queue of partition keys ordered by expiry time.
    ///
    /// When the cache is pruned, expired records are removed first.
    ///
    /// INVARIANT: the keys in here are exactly the keys in `partitions`.
    expiry_priority: PriorityQueue<K1, Reverse<Instant>>,

    /// The number of records in the cache, across all partitions.
    ///
    /// INVARIANT: this is the sum of the `size` fields of the `partitions`.
    current_size: usize,

    /// The desired maximum number of records in the cache.
    desired_size: usize,
}

/// The cached records for a domain.
#[derive(Debug, Clone, Eq, PartialEq)]
struct Partition<K: Eq + Hash, V> {
    /// The time this partition was last read at.
    last_read: Instant,

    /// When the next record expires.
    ///
    /// INVARIANT: this is the minimum of the expiry times of the `records`.
    next_expiry: Instant,

    /// How many records there are.
    ///
    /// INVARIANT: this is the sum of the vector lengths in `records`.
    size: usize,

    /// The records, further divided by record key.
    records: HashMap<K, Vec<(V, Instant)>>,
}

impl<K1: Clone + Eq + Hash, K2: Copy + Eq + Hash, V: PartialEq> Default
    for PartitionedCache<K1, K2, V>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K1: Clone + Eq + Hash, K2: Copy + Eq + Hash, V: PartialEq> PartitionedCache<K1, K2, V> {
    /// Create a new cache with a default desired size.
    pub fn new() -> Self {
        Self::with_desired_size(512)
    }

    /// Create a new cache with the given desired size.
    ///
    /// The `prune` method will remove expired records, and also enough records
    /// (in least-recently-used order) to get down to this size.
    pub fn with_desired_size(desired_size: usize) -> Self {
        Self {
            // `desired_size / 2` is a compromise: most partitions will have
            // more than one record, so `desired_size` would be too big for the
            // `partitions`.
            partitions: HashMap::with_capacity(desired_size / 2),
            access_priority: PriorityQueue::with_capacity(desired_size),
            expiry_priority: PriorityQueue::with_capacity(desired_size),
            current_size: 0,
            desired_size,
        }
    }

    /// Get all records for the given partition key from the cache, along with
    /// their expiration times.
    ///
    /// These records may have expired if `prune` has not been called recently.
    pub fn get_partition_without_checking_expiration(
        &mut self,
        partition_key: &K1,
    ) -> Option<&HashMap<K2, Vec<(V, Instant)>>> {
        if let Some(partition) = self.partitions.get_mut(partition_key) {
            partition.last_read = Instant::now();
            self.access_priority
                .change_priority(partition_key, Reverse(partition.last_read));
            return Some(&partition.records);
        }

        None
    }

    /// Get all records for the given partition and record key from the cache,
    /// along with their expiration times.
    ///
    /// These records may have expired if `prune` has not been called recently.
    pub fn get_without_checking_expiration(
        &mut self,
        partition_key: &K1,
        record_key: &K2,
    ) -> Option<&[(V, Instant)]> {
        if let Some(partition) = self.partitions.get_mut(partition_key) {
            if let Some(tuples) = partition.records.get(record_key) {
                partition.last_read = Instant::now();
                self.access_priority
                    .change_priority(partition_key, Reverse(partition.last_read));
                return Some(tuples);
            }
        }

        None
    }

    /// Insert a record into the cache, or reset the expiry time if already
    /// present.
    pub fn upsert(&mut self, partition_key: K1, record_key: K2, value: V, ttl: Duration) {
        let now = Instant::now();
        let expiry = now + ttl;
        let tuple = (value, expiry);
        if let Some(partition) = self.partitions.get_mut(&partition_key) {
            if let Some(tuples) = partition.records.get_mut(&record_key) {
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
                    partition.size -= 1;
                    self.current_size -= 1;

                    if dup_expiry == partition.next_expiry {
                        let mut new_next_expiry = expiry;
                        for (_, e) in tuples {
                            if *e < new_next_expiry {
                                new_next_expiry = *e;
                            }
                        }
                        partition.next_expiry = new_next_expiry;
                        self.expiry_priority
                            .change_priority(&partition_key, Reverse(partition.next_expiry));
                    }
                }
            } else {
                partition.records.insert(record_key, vec![tuple]);
            }
            partition.last_read = now;
            partition.size += 1;
            self.access_priority
                .change_priority(&partition_key, Reverse(partition.last_read));
            if expiry < partition.next_expiry {
                partition.next_expiry = expiry;
                self.expiry_priority
                    .change_priority(&partition_key, Reverse(partition.next_expiry));
            }
        } else {
            let mut records = HashMap::new();
            records.insert(record_key, vec![tuple]);
            let partition = Partition {
                last_read: now,
                next_expiry: expiry,
                size: 1,
                records,
            };
            self.access_priority
                .push(partition_key.clone(), Reverse(partition.last_read));
            self.expiry_priority
                .push(partition_key.clone(), Reverse(partition.next_expiry));
            self.partitions.insert(partition_key, partition);
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
        if let Some((partition_key, Reverse(expiry))) = self.expiry_priority.pop() {
            let now = Instant::now();

            if expiry > now {
                self.expiry_priority.push(partition_key, Reverse(expiry));
                return 0;
            }

            if let Some(partition) = self.partitions.get_mut(&partition_key) {
                let mut pruned = 0;

                let record_keys = partition.records.keys().copied().collect::<Vec<K2>>();
                let mut next_expiry = None;
                for rkey in record_keys {
                    if let Some(tuples) = partition.records.get_mut(&rkey) {
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

                partition.size -= pruned;

                if let Some(ne) = next_expiry {
                    partition.next_expiry = ne;
                    self.expiry_priority.push(partition_key, Reverse(ne));
                } else {
                    self.partitions.remove(&partition_key);
                    self.access_priority.remove(&partition_key);
                }

                self.current_size -= pruned;
                pruned
            } else {
                self.access_priority.remove(&partition_key);
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
        if let Some((partition_key, _)) = self.access_priority.pop() {
            self.expiry_priority.remove(&partition_key);

            if let Some(partition) = self.partitions.remove(&partition_key) {
                let pruned = partition.size;
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
                &cache.get_without_checking_expiration(
                    &rr.name,
                    QueryType::Record(rr.rtype_with_data.rtype()),
                ),
            );
            assert_cache_response(
                &rr,
                &cache.get_without_checking_expiration(&rr.name, QueryType::Wildcard),
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

        assert_eq!(1, cache.inner.current_size);
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
            cache.get_without_checking_expiration(&name, qtype);
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
        assert!(cache.inner.current_size <= 25);
        assert_eq!(cache.inner.current_size, current_size);
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

        assert_eq!(49, cache.inner.remove_expired());
        assert_eq!(51, cache.inner.current_size);
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
        assert_eq!(cache.inner.current_size, current_size);
        assert_invariants(&cache);
    }

    fn assert_invariants(cache: &Cache) {
        assert_eq!(
            cache.inner.current_size,
            cache
                .inner
                .partitions
                .values()
                .map(|e| e.size)
                .sum::<usize>()
        );

        assert_eq!(
            cache.inner.partitions.len(),
            cache.inner.access_priority.len()
        );
        assert_eq!(
            cache.inner.partitions.len(),
            cache.inner.expiry_priority.len()
        );

        let mut access_priority = PriorityQueue::new();
        let mut expiry_priority = PriorityQueue::new();

        for (name, partition) in &cache.inner.partitions {
            assert_eq!(
                partition.size,
                partition.records.values().map(Vec::len).sum::<usize>()
            );

            let mut min_expires = None;
            for (rtype, tuples) in &partition.records {
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

            assert_eq!(Some(partition.next_expiry), min_expires);

            access_priority.push(name.clone(), Reverse(partition.last_read));
            expiry_priority.push(name.clone(), Reverse(partition.next_expiry));
        }

        assert_eq!(cache.inner.access_priority, access_priority);
        assert_eq!(cache.inner.expiry_priority, expiry_priority);
    }
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc)]
pub mod test_util {
    use super::*;

    /// Assert that the cache response has exactly one element and
    /// that it matches the original (all fields equal except TTL,
    /// where the original is >=).
    pub fn assert_cache_response(original: &ResourceRecord, response: &[ResourceRecord]) {
        assert_eq!(1, response.len());
        let cached = response[0].clone();

        assert_eq!(original.name, cached.name);
        assert_eq!(original.rtype_with_data, cached.rtype_with_data);
        assert_eq!(RecordClass::IN, cached.rclass);
        assert!(original.ttl >= cached.ttl);
    }
}
