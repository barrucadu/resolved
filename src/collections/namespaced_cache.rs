use priority_queue::PriorityQueue;
use std::cmp::{Eq, PartialEq, Reverse};
use std::collections::HashMap;
use std::hash::Hash;
use std::time::Instant;

/// A size-bounded cache, using LRU (Least Recently Used) eviction
/// order, with entry expiration.  Entries are stored under a
/// namespaced key, which allows efficient retrieval of all entries
/// under the top-level key.
#[derive(Debug, Clone)]
pub struct NamespacedCache<Kn: Eq + Hash, Ki: Eq + Hash, V> {
    /// Cached records, indexed by namespace key.
    namespaces: HashMap<Kn, Namespace<Ki, V>>,

    /// Priority queue of namespace keys ordered by access times.
    ///
    /// When the cache is full and there are no expired records to
    /// prune, namespaces will instead be pruned in LRU order.
    ///
    /// INVARIANT: the keys in here are exactly the keys in
    /// `namespaces`.
    access_priority: PriorityQueue<Kn, Reverse<Instant>>,

    /// Priority queue of namespace keys ordered by expiry time.
    ///
    /// When the cache is pruned, expired entries are removed first.
    ///
    /// INVARIANT: the keys in here are exactly the keys in
    /// `namespaces`.
    expiry_priority: PriorityQueue<Kn, Reverse<Instant>>,

    /// The number of entries in the cache.
    ///
    /// INVARIANT: this is the sum of the `size` fields of the
    /// `namespaces`.
    current_size: usize,

    /// The desired maximum number of records in the cache.
    desired_size: usize,
}

/// The cached entries under a specific namespace.
#[derive(Debug, Clone, Eq, PartialEq)]
struct Namespace<Ki: Eq + Hash, V> {
    /// The time these entries were last read at.
    last_read: Instant,

    /// When the next entry expires.
    ///
    /// INVARIANT: this is the minimum of the expiry times of the
    /// entries.
    next_expiry: Instant,

    /// How many entries there are.
    ///
    /// INVARIANT: this is the sum of the vector lengths in `entries`.
    size: usize,

    /// The entries, divided by key.
    entries: HashMap<Ki, Vec<Entry<V>>>,
}

/// An entry in the cache.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Entry<V> {
    pub value: V,
    pub expires_at: Instant,
}

impl<Kn: Clone + Eq + Hash, Ki: Eq + Hash, V: Clone + PartialEq> Default
    for NamespacedCache<Kn, Ki, V>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Kn: Clone + Eq + Hash, Ki: Eq + Hash, V: Clone + PartialEq> NamespacedCache<Kn, Ki, V> {
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
        // allocate space for 32 entries beyond the desired size,
        // since pruning is not done synchronously with insertion
        Self::with_desired_size_and_flex(desired_size, 32)
    }

    /// Create a new cache with the given desired size and flex.
    ///
    /// If the number of entries exceeds the desired size, expired and
    /// least-recently-used items will be pruned.  To reduce the
    /// likelihood of needing to grow the internal data structures,
    /// they are sized to hold `desired_size + flex` entries.
    ///
    /// Panics:
    ///
    /// - If called with a desired_size of 0.
    pub fn with_desired_size_and_flex(desired_size: usize, flex: usize) -> Self {
        if desired_size == 0 {
            panic!("cannot create a zero-size cache");
        }

        let capacity = desired_size + flex;

        Self {
            // `capacity / 2` is based on the assumption that most
            // namespaces will have more than one entry inside them.
            namespaces: HashMap::with_capacity(capacity / 2),
            access_priority: PriorityQueue::with_capacity(capacity),
            expiry_priority: PriorityQueue::with_capacity(capacity),
            current_size: 0,
            desired_size,
        }
    }

    /// Return the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.current_size
    }

    /// Return whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.current_size == 0
    }

    /// Get all entries from the cache matching the namespace key,
    /// regardless of inner key.
    ///
    /// If any expired entries are retrieved, they are removed and the
    /// cache is evicted.
    pub fn get_all(&mut self, now: Instant, namespace_key: &Kn) -> Vec<Entry<V>> {
        let mut out = self.get_all_without_checking_expiration(now, namespace_key);
        let len = out.len();
        out.retain(|x| x.expires_at > now);
        if out.len() != len {
            self.remove_expired(now);
        }
        out
    }

    /// Get all entries from the cache matching the namespace key,
    /// regardless of inner key.
    ///
    /// These entries may have expired.  Consumers MUST check before
    /// using the record!
    pub fn get_all_without_checking_expiration(
        &mut self,
        now: Instant,
        namespace_key: &Kn,
    ) -> Vec<Entry<V>> {
        if let Some(namespace) = self.namespaces.get_mut(namespace_key) {
            let mut out = Vec::with_capacity(namespace.size);
            for entries in namespace.entries.values() {
                out.append(&mut entries.clone());
            }
            if !out.is_empty() {
                namespace.last_read = now;
                self.access_priority
                    .change_priority(namespace_key, Reverse(namespace.last_read));
            }
            out
        } else {
            Vec::new()
        }
    }

    /// Get all entries from the cache matching both the namespace and
    /// inner keys.
    ///
    /// If any expired entries are retrieved, they are removed and the
    /// cache is evicted.
    pub fn get(&mut self, now: Instant, namespace_key: &Kn, inner_key: &Ki) -> Vec<Entry<V>> {
        let mut out = self.get_without_checking_expiration(now, namespace_key, inner_key);
        let len = out.len();
        out.retain(|x| x.expires_at > now);
        if out.len() != len {
            self.remove_expired(now);
        }
        out
    }

    /// Get all entries from the cache matching both the namespace and
    /// inner keys.
    ///
    /// These entries may have expired.  Consumers MUST check before
    /// using the record!
    pub fn get_without_checking_expiration(
        &mut self,
        now: Instant,
        namespace_key: &Kn,
        inner_key: &Ki,
    ) -> Vec<Entry<V>> {
        if let Some(namespace) = self.namespaces.get_mut(namespace_key) {
            if let Some(entries) = namespace.entries.get(inner_key) {
                if !entries.is_empty() {
                    namespace.last_read = now;
                    self.access_priority
                        .change_priority(namespace_key, Reverse(namespace.last_read));
                }
                entries.clone()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    }

    /// Insert an entry into the cache.
    ///
    /// If it is equal to an entry already in the cache, the
    /// expiration time of the existing entry is updated instead.
    pub fn insert(
        &mut self,
        now: Instant,
        namespace_key: Kn,
        inner_key: Ki,
        value: V,
        expires_at: Instant,
    ) {
        if let Some(namespace) = self.namespaces.get_mut(&namespace_key) {
            if let Some(entries) = namespace.entries.get_mut(&inner_key) {
                let mut duplicate_expires_at = None;
                for i in 0..entries.len() {
                    let entry = &entries[i];
                    if entry.value == value {
                        duplicate_expires_at = Some(entry.expires_at);
                        entries.swap_remove(i);
                        break;
                    }
                }

                entries.push(Entry { value, expires_at });

                if let Some(dup_expiry) = duplicate_expires_at {
                    namespace.size -= 1;
                    self.current_size -= 1;

                    if dup_expiry == namespace.next_expiry {
                        namespace.next_expiry = entries
                            .iter()
                            .map(|e| e.expires_at)
                            .min()
                            .unwrap_or(expires_at);
                        self.expiry_priority
                            .change_priority(&namespace_key, Reverse(namespace.next_expiry));
                    }
                }
            } else {
                namespace
                    .entries
                    .insert(inner_key, vec![Entry { value, expires_at }]);
            }

            namespace.last_read = now;
            namespace.size += 1;

            self.access_priority
                .change_priority(&namespace_key, Reverse(namespace.last_read));

            if expires_at < namespace.next_expiry {
                namespace.next_expiry = expires_at;
                self.expiry_priority
                    .change_priority(&namespace_key, Reverse(namespace.next_expiry));
            }
        } else {
            let mut entries = HashMap::new();
            entries.insert(inner_key, vec![Entry { value, expires_at }]);
            let namespace = Namespace {
                last_read: now,
                next_expiry: expires_at,
                size: 1,
                entries,
            };
            self.access_priority
                .push(namespace_key.clone(), Reverse(namespace.last_read));
            self.expiry_priority
                .push(namespace_key.clone(), Reverse(namespace.next_expiry));
            self.namespaces.insert(namespace_key, namespace);
        }

        self.current_size += 1;
    }

    /// Delete all expired records.
    ///
    /// Returns the number of records deleted.
    pub fn remove_expired(&mut self, now: Instant) -> usize {
        let mut pruned = 0;

        loop {
            let before = pruned;
            pruned += self.remove_expired_step(now);
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
    /// Returns the number of records deleted.
    pub fn prune(&mut self, now: Instant) -> usize {
        if self.current_size <= self.desired_size {
            return 0;
        }

        let mut pruned = self.remove_expired(now);

        while self.current_size > self.desired_size {
            pruned += self.remove_least_recently_used();
        }

        pruned
    }

    /// Helper for `remove_expired`: looks at the next-to-expire
    /// domain and cleans up expired records from it.  This may delete
    /// more than one record, and may even delete the whole domain.
    ///
    /// Returns the number of records removed.
    fn remove_expired_step(&mut self, now: Instant) -> usize {
        if let Some((namespace_key, Reverse(expiry))) = self.expiry_priority.pop() {
            if expiry > now {
                self.expiry_priority.push(namespace_key, Reverse(expiry));
                return 0;
            }

            if let Some(namespace) = self.namespaces.get_mut(&namespace_key) {
                let mut pruned = 0;

                let mut next_expiry = None;
                for entries in namespace.entries.values_mut() {
                    let len = entries.len();
                    entries.retain(|e| e.expires_at > now);
                    pruned += len - entries.len();
                    for e in entries {
                        next_expiry = match next_expiry {
                            Some(t) => Some(std::cmp::min(t, e.expires_at)),
                            None => Some(e.expires_at),
                        };
                    }
                }

                namespace.size -= pruned;

                if let Some(ne) = next_expiry {
                    println!(
                        "setting next expiry from {:?} to {:?}",
                        namespace.next_expiry, ne
                    );
                    namespace.next_expiry = ne;
                    self.expiry_priority.push(namespace_key, Reverse(ne));
                } else {
                    self.namespaces.remove(&namespace_key);
                    self.access_priority.remove(&namespace_key);
                }

                self.current_size -= pruned;
                pruned
            } else {
                self.access_priority.remove(&namespace_key);
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
        if let Some((namespace_key, _)) = self.access_priority.pop() {
            self.expiry_priority.remove(&namespace_key);

            if let Some(namespace) = self.namespaces.remove(&namespace_key) {
                self.current_size -= namespace.size;
                namespace.size
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
    use std::time::Duration;

    use super::*;

    // the cache doesn't depend on the wire types, but it's convenient
    // to re-use a random test data generator I already have.
    use crate::protocol::wire_types::test_util::*;
    use crate::protocol::wire_types::*;

    #[test]
    fn cache_put_deduplicates_and_maintains_invariants() {
        let now = Instant::now();
        let mut cache = NamespacedCache::new();
        let rr = arbitrary_resourcerecord();

        insert_rr(now, &mut cache, rr.clone());
        insert_rr(now, &mut cache, rr);

        assert_eq!(1, cache.len());
        assert_invariants(&cache);
    }

    #[test]
    fn cache_put_maintains_invariants() {
        let now = Instant::now();
        let mut cache = NamespacedCache::new();

        for _ in 0..100 {
            insert_rr(now, &mut cache, arbitrary_resourcerecord());
        }

        assert_invariants(&cache);
    }

    #[test]
    fn cache_put_then_get_maintains_invariants() {
        let now = Instant::now();
        let mut cache = NamespacedCache::new();
        let mut queries = Vec::new();

        for _ in 0..100 {
            let rr = arbitrary_resourcerecord();
            insert_rr(now, &mut cache, rr.clone());
            queries.push((rr.name.clone(), rr.rtype_with_data.rtype()));
        }
        for (namespace_key, inner_key) in queries {
            cache.get_without_checking_expiration(now, &namespace_key, &inner_key);
        }

        assert_invariants(&cache);
    }

    #[test]
    fn cache_put_then_prune_maintains_invariants() {
        let now = Instant::now();
        let mut cache = NamespacedCache::with_desired_size(25);

        for _ in 0..100 {
            let mut rr = arbitrary_resourcerecord();
            rr.ttl = 300; // not testing expiry in this case
            insert_rr(now, &mut cache, rr);
        }

        assert_eq!(75, cache.prune(now));
        assert_eq!(25, cache.len());
        assert_invariants(&cache);
    }

    #[test]
    fn cache_put_then_expire_maintains_invariants() {
        let now = Instant::now();
        let mut cache = NamespacedCache::new();

        for i in 0..100 {
            let mut rr = arbitrary_resourcerecord();
            rr.ttl = if i > 0 && i % 2 == 0 { 0 } else { 300 };
            insert_rr(now, &mut cache, rr);
        }

        assert_eq!(49, cache.remove_expired(now));
        assert_eq!(51, cache.current_size);
        assert_invariants(&cache);
    }

    #[test]
    fn cache_prune_expires_all() {
        let now = Instant::now();
        let mut cache = NamespacedCache::with_desired_size(99);

        for i in 0..100 {
            let mut rr = arbitrary_resourcerecord();
            rr.ttl = if i > 0 && i % 2 == 0 { 0 } else { 300 };
            insert_rr(now, &mut cache, rr);
        }

        assert_eq!(49, cache.prune(now));
    }

    fn insert_rr(
        now: Instant,
        cache: &mut NamespacedCache<DomainName, RecordType, (RecordTypeWithData, RecordClass)>,
        rr: ResourceRecord,
    ) {
        cache.insert(
            now,
            rr.name,
            rr.rtype_with_data.rtype(),
            (rr.rtype_with_data, rr.rclass),
            now + Duration::from_secs(rr.ttl as u64),
        );
    }

    fn assert_invariants(
        cache: &NamespacedCache<DomainName, RecordType, (RecordTypeWithData, RecordClass)>,
    ) {
        assert_eq!(
            cache.current_size,
            cache.namespaces.values().map(|e| e.size).sum::<usize>()
        );

        assert_eq!(cache.namespaces.len(), cache.access_priority.len());
        assert_eq!(cache.namespaces.len(), cache.expiry_priority.len());

        let mut access_priority = PriorityQueue::new();
        let mut expiry_priority = PriorityQueue::new();

        for (namespace_key, namespace) in cache.namespaces.iter() {
            let size = namespace.entries.values().map(|r| r.len()).sum::<usize>();

            let next_expiry = namespace
                .entries
                .values()
                .filter_map(|vs| vs.iter().map(|v| v.expires_at).min())
                .min();

            assert_eq!(size, namespace.size);
            assert_eq!(next_expiry, Some(namespace.next_expiry));

            access_priority.push(namespace_key.clone(), Reverse(namespace.last_read));
            expiry_priority.push(namespace_key.clone(), Reverse(namespace.next_expiry));
        }

        assert_eq!(cache.access_priority, access_priority);
        assert_eq!(cache.expiry_priority, expiry_priority);
    }
}
