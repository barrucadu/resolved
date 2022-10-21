use std::collections::HashSet;
use std::fmt::Write as _;

use crate::hosts::types::*;
use crate::protocol::types::*;

impl Hosts {
    pub fn serialise(&self) -> String {
        let mut out = String::new();

        let sorted_domains = {
            let mut set = HashSet::new();
            for name in self.v4.keys() {
                set.insert(name);
            }
            for name in self.v6.keys() {
                set.insert(name);
            }
            let mut vec = set.into_iter().collect::<Vec<&DomainName>>();
            vec.sort();
            vec
        };

        for domain in sorted_domains {
            let domain_str = if domain.is_root() {
                ".".to_string()
            } else {
                let mut name_without_dot = domain.to_dotted_string();
                name_without_dot.pop();
                name_without_dot
            };

            if let Some(addr) = self.v4.get(domain) {
                let _ = writeln!(&mut out, "{addr} {domain_str}");
            }
            if let Some(addr) = self.v6.get(domain) {
                let _ = writeln!(&mut out, "{addr} {domain_str}");
            }
            out.push('\n');
        }

        out
    }
}
