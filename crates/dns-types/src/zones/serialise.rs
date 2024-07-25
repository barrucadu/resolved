use bytes::Bytes;
use std::collections::HashSet;
use std::fmt::Write as _;

use crate::protocol::types::*;
use crate::zones::types::*;

impl Zone {
    pub fn serialise(&self) -> String {
        let mut out = String::new();

        if let Some(soa) = self.get_soa() {
            let show_origin = !self.get_apex().is_root();
            let serialised_apex = serialise_octets(
                &self
                    .get_apex()
                    .to_dotted_string()
                    .bytes()
                    .collect::<Bytes>(),
                false,
            );

            if show_origin {
                _ = writeln!(&mut out, "$ORIGIN {serialised_apex}");
                out.push('\n');
            }

            _ = writeln!(
                &mut out,
                "{} IN SOA {}",
                if show_origin { "@" } else { &serialised_apex },
                self.serialise_rdata(&soa.to_rdata()),
            );
            out.push('\n');
        }

        let all_records = self.all_records();
        let all_wildcard_records = self.all_wildcard_records();

        let sorted_domains = {
            let mut set = HashSet::new();
            for name in all_records.keys() {
                set.insert(*name);
            }
            for name in all_wildcard_records.keys() {
                set.insert(*name);
            }
            let mut vec = set.into_iter().collect::<Vec<&DomainName>>();
            vec.sort();
            vec
        };

        for domain in sorted_domains {
            if let Some(zrs) = all_records.get(domain) {
                let has_wildcards = all_wildcard_records.contains_key(domain);
                for zr in zrs {
                    if zr.rtype_with_data.rtype() == RecordType::SOA {
                        // already handled above, and it's invalid for
                        // a zone to have multiple SOA records
                        continue;
                    }

                    _ = writeln!(
                        &mut out,
                        "{}{} {} IN {} {}",
                        self.serialise_domain(domain),
                        if has_wildcards { "  " } else { "" },
                        zr.ttl,
                        zr.rtype_with_data.rtype(),
                        self.serialise_rdata(&zr.rtype_with_data)
                    );
                }
            }
            if let Some(zrs) = all_wildcard_records.get(domain) {
                for zr in zrs {
                    _ = writeln!(
                        &mut out,
                        "*.{} {} IN {} {}",
                        self.serialise_domain(domain),
                        zr.ttl,
                        zr.rtype_with_data.rtype(),
                        self.serialise_rdata(&zr.rtype_with_data)
                    );
                }
            }
            out.push('\n');
        }

        out
    }

    /// Serialise a domain name: dotted string format, with the apex
    /// chopped off if this is an authoritative zone (unless the apex
    /// is the root domain, because that's only a single character
    /// long so we may as well show it).
    fn serialise_domain(&self, name: &DomainName) -> String {
        let domain_str = {
            let apex = self.get_apex();
            if apex.is_root() || !self.is_authoritative() || !name.is_subdomain_of(apex) {
                name.to_dotted_string()
            } else if name == apex {
                "@".to_string()
            } else {
                let labels_to_keep = name.labels.len() - apex.labels.len();
                DomainName {
                    labels: Vec::from(&name.labels[..labels_to_keep]),
                    len: name.len - apex.len,
                }
                .to_dotted_string()
            }
        };

        serialise_octets(&domain_str.bytes().collect::<Bytes>(), false)
    }

    /// Serialise the RDATA, with domains displayed relative to the apex (if
    /// authoritative).
    pub fn serialise_rdata(&self, rtype_with_data: &RecordTypeWithData) -> String {
        match rtype_with_data {
            RecordTypeWithData::A { address } => format!("{address}"),
            RecordTypeWithData::NS { nsdname } => self.serialise_domain(nsdname),
            RecordTypeWithData::MD { madname } => self.serialise_domain(madname),
            RecordTypeWithData::MF { madname } => self.serialise_domain(madname),
            RecordTypeWithData::CNAME { cname } => self.serialise_domain(cname),
            RecordTypeWithData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => format!(
                "{} {} {serial} {refresh} {retry} {expire} {minimum}",
                self.serialise_domain(mname),
                self.serialise_domain(rname),
            ),
            RecordTypeWithData::MB { madname } => self.serialise_domain(madname),
            RecordTypeWithData::MG { mdmname } => self.serialise_domain(mdmname),
            RecordTypeWithData::MR { newname } => self.serialise_domain(newname),
            RecordTypeWithData::NULL { octets } => serialise_octets(octets, true),
            RecordTypeWithData::WKS { octets } => serialise_octets(octets, true),
            RecordTypeWithData::PTR { ptrdname } => self.serialise_domain(ptrdname),
            RecordTypeWithData::HINFO { octets } => serialise_octets(octets, true),
            RecordTypeWithData::MINFO { rmailbx, emailbx } => format!(
                "{} {}",
                self.serialise_domain(rmailbx),
                self.serialise_domain(emailbx)
            ),
            RecordTypeWithData::MX {
                preference,
                exchange,
            } => format!("{preference} {}", self.serialise_domain(exchange)),
            RecordTypeWithData::TXT { octets } => serialise_octets(octets, true),
            RecordTypeWithData::AAAA { address } => format!("{address}"),
            RecordTypeWithData::SRV {
                priority,
                weight,
                port,
                target,
            } => format!(
                "{priority} {weight} {port} {}",
                self.serialise_domain(target)
            ),
            RecordTypeWithData::Unknown { octets, .. } => serialise_octets(octets, true),
        }
    }
}

/// Serialise a string of octets to a quoted or unquoted string with
/// the appropriate escaping.
fn serialise_octets(octets: &[u8], quoted: bool) -> String {
    let mut out = String::with_capacity(2 + octets.len());

    if quoted {
        out.push('"');
    }

    for octet in octets {
        if *octet == b'"' || *octet == b'\\' || *octet == b';' || *octet == b'(' || *octet == b')' {
            out.push('\\');
            out.push(*octet as char);
        } else if *octet < 32 || *octet > 126 || (*octet == 32 && !quoted) {
            out.push('\\');
            let digit3 = *octet % 10;
            let digit2 = (*octet / 10) % 10;
            let digit1 = (*octet / 100) % 10;
            out.push((digit1 + 48) as char);
            out.push((digit2 + 48) as char);
            out.push((digit3 + 48) as char);
        } else {
            out.push(*octet as char);
        }
    }

    if quoted {
        out.push('"');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialise_octets_special() {
        assert_eq!("\\012", serialise_octets(&[12], false));
        assert_eq!("\\234", serialise_octets(&[234], false));

        assert_eq!("\\\\", serialise_octets(b"\\", false));
        assert_eq!("\\\"", serialise_octets(b"\"", false));
    }

    #[test]
    fn serialise_octets_space() {
        assert_eq!("\\032", serialise_octets(b" ", false));
        assert_eq!("\" \"", serialise_octets(b" ", true));
    }
}
