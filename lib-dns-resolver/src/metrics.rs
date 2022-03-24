use std::net::{Ipv4Addr, Ipv6Addr};

use dns_types::protocol::types::*;
use dns_types::zones::types::*;

/// The A record for a blocked question
pub const BLOCKED_A: RecordTypeWithData = RecordTypeWithData::A {
    address: Ipv4Addr::UNSPECIFIED,
};

/// The AAAA record for a blocked question
pub const BLOCKED_AAAA: RecordTypeWithData = RecordTypeWithData::AAAA {
    address: Ipv6Addr::UNSPECIFIED,
};

/// Metrics from a resolution attempt.  The resolvers build this
/// structure rather than update the Prometheus metrics directly.
pub struct Metrics {
    /// Hits on authoritative data: zone authoritative answers,
    /// CNAMEs, delegations, and name errors.  Does not include
    /// blocked domains.
    pub authoritative_hits: u64,
    /// Hits on non-authoritative data: zone non-authoritative answers
    /// and CNAMEs (zone non-authoritative delegations and name errors
    /// are ignored).  Does not include blocked domains.
    pub override_hits: u64,
    /// A or AAAA questions (ie, not *) where the result is from a
    /// zone and has the unspecified IP.
    pub blocked: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Questions which are answered by some upstream nameserver.
    pub nameserver_hits: u64,
    /// Questions which an upstream nameserver fails to answer.
    pub nameserver_misses: u64,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            authoritative_hits: 0,
            override_hits: 0,
            blocked: 0,
            cache_misses: 0,
            cache_hits: 0,
            nameserver_hits: 0,
            nameserver_misses: 0,
        }
    }

    pub fn zoneresult_answer(&mut self, rrs: &[ResourceRecord], zone: &Zone, question: &Question) {
        if rrs.len() == 1 {
            let rtype = &rrs[0].rtype_with_data;
            if (question.qtype == QueryType::Record(RecordType::A) && rtype == &BLOCKED_A)
                || (question.qtype == QueryType::Record(RecordType::AAAA) && rtype == &BLOCKED_AAAA)
            {
                self.blocked += 1;
                return;
            }
        }

        if zone.is_authoritative() {
            self.authoritative_hits += 1;
        } else {
            self.override_hits += 1;
        }
    }

    pub fn zoneresult_cname(&mut self, zone: &Zone) {
        if zone.is_authoritative() {
            self.authoritative_hits += 1;
        } else {
            self.override_hits += 1;
        }
    }

    pub fn zoneresult_delegation(&mut self, zone: &Zone) {
        if zone.is_authoritative() {
            self.authoritative_hits += 1;
        }
    }

    pub fn zoneresult_nameerror(&mut self, zone: &Zone) {
        if zone.is_authoritative() {
            self.authoritative_hits += 1;
        }
    }

    pub fn cache_hit_or_miss(&mut self, cached_rrs: &[ResourceRecord]) {
        if cached_rrs.is_empty() {
            self.cache_misses += 1;
        } else {
            self.cache_hits += 1;
        }
    }

    pub fn nameserver_hit(&mut self) {
        self.nameserver_hits += 1;
    }

    pub fn nameserver_miss(&mut self) {
        self.nameserver_misses += 1;
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
