use config::{Config, ConfigError, File};
use serde::de::{self, Deserializer, Unexpected, Visitor};
use serde::Deserialize;
use std::fmt;
use std::net::Ipv4Addr;

use crate::protocol::DomainName;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Default)]
pub struct Settings {
    #[serde(default)]
    pub upstream_nameservers: Vec<Ipv4Addr>,
    #[serde(default)]
    pub blocked_domains: Vec<DomainWithOptionalSubdomains>,
    #[serde(default)]
    pub static_records: Vec<Record>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct Record {
    pub domain: DomainWithOptionalSubdomains,
    #[serde(rename = "a")]
    pub record_a: Option<Ipv4Addr>,
    #[serde(rename = "cname")]
    pub record_cname: Option<Name>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct DomainWithOptionalSubdomains {
    pub name: Name,
    #[serde(default)]
    pub include_subdomains: bool,
}

impl DomainWithOptionalSubdomains {
    pub fn matches(&self, other: &DomainName) -> bool {
        if self.include_subdomains {
            other.is_subdomain_of(&self.name.domain)
        } else {
            other.octets == self.name.domain.octets
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Name {
    pub domain: DomainName,
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NameVisitor;

        impl<'de> Visitor<'de> for NameVisitor {
            type Value = Name;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Name")
            }

            fn visit_str<E>(self, v: &str) -> Result<Name, E>
            where
                E: de::Error,
            {
                match DomainName::from_dotted_string(v) {
                    Some(domain) => Ok(Name { domain }),
                    None => {
                        return Err(de::Error::invalid_value(
                            Unexpected::Str(v),
                            &"a valid domain name",
                        ))
                    }
                }
            }
        }

        deserializer.deserialize_str(NameVisitor)
    }
}

impl Settings {
    pub fn new(filename: &str) -> Result<Self, ConfigError> {
        Config::builder()
            .add_source(File::with_name(filename))
            .build()?
            .try_deserialize()
    }
}
