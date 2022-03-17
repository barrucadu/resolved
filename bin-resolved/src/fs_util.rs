use std::io;
use std::path::{Path, PathBuf};
use tokio::fs::{read_dir, read_to_string};

use dns_types::hosts::types::Hosts;
use dns_types::zones::types::Zone;

/// Read a hosts file, for example /etc/hosts.
pub async fn hosts_from_file<P: AsRef<Path>>(
    path: P,
) -> io::Result<Result<Hosts, dns_types::hosts::deserialise::Error>> {
    let data = read_to_string(path).await?;
    Ok(Hosts::deserialise(&data))
}

/// Read a zone file.
///
/// If it has a SOA record, it is an authoritative zone: it may
/// only have *one* SOA record, and all RRs must be subdomains of
/// the SOA domain.
///
/// If it does not have a SOA record, it is a non-authoritative
/// zone, and the root domain will be used for its apex.
pub async fn zone_from_file<P: AsRef<Path>>(
    path: P,
) -> io::Result<Result<Zone, dns_types::zones::deserialise::Error>> {
    let data = read_to_string(path).await?;
    Ok(Zone::deserialise(&data))
}

/// Get files from a directory, sorted.
pub async fn get_files_from_dir(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();

    let mut reader = read_dir(dir).await?;
    while let Some(entry) = reader.next_entry().await? {
        let path = entry.path();
        if !path.is_dir() {
            out.push(path);
        }
    }

    out.sort();
    Ok(out)
}
