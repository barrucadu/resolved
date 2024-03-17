use dns_types::protocol::types::*;
use dns_types::zones::types::Zones;

use crate::cache::SharedCache;
use crate::metrics::Metrics;

pub struct Context<'a, CT> {
    // global context
    pub r: CT,
    pub zones: &'a Zones,
    pub cache: &'a SharedCache,
    // request state
    question_stack: Vec<Question>,
    metrics: Metrics,
}

impl<'a, CT> Context<'a, CT> {
    pub fn new(r: CT, zones: &'a Zones, cache: &'a SharedCache, recursion_limit: usize) -> Self {
        Self {
            r,
            zones,
            cache,
            question_stack: Vec::with_capacity(recursion_limit),
            metrics: Metrics::new(),
        }
    }

    pub fn metrics(&mut self) -> &mut Metrics {
        &mut self.metrics
    }

    pub fn done(self) -> Metrics {
        self.metrics
    }

    pub fn at_recursion_limit(&self) -> bool {
        self.question_stack.len() == self.question_stack.capacity()
    }

    pub fn is_duplicate_question(&self, question: &Question) -> bool {
        self.question_stack.contains(question)
    }

    pub fn push_question(&mut self, question: &Question) {
        self.question_stack.push(question.clone());
    }

    pub fn pop_question(&mut self) {
        self.question_stack.pop();
    }
}
