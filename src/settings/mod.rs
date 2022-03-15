use config::{Config, ConfigError, File};
use serde::Deserialize;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Deserialize, Default)]
pub struct Settings {
    #[serde(default)]
    pub interface: Option<Ipv4Addr>,
    #[serde(default)]
    pub hosts_files: Vec<String>,
    #[serde(default)]
    pub zone_files: Vec<String>,
}

impl Settings {
    pub fn new(filename: &str) -> Result<Self, ConfigError> {
        Config::builder()
            .add_source(File::with_name(filename))
            .build()?
            .try_deserialize()
    }
}
