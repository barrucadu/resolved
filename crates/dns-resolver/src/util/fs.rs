use std::io;
use std::path::{Path, PathBuf};
use tokio::fs::{read_dir, read_to_string};

use dns_types::hosts::types::Hosts;
use dns_types::zones::types::{Zone, Zones};

/// Load the hosts and zones from the configuration, generating the
/// `Zones` parameter for the resolver.
pub async fn load_zone_configuration(
    hosts_files: &[PathBuf],
    hosts_dirs: &[PathBuf],
    zone_files: &[PathBuf],
    zone_dirs: &[PathBuf],
) -> Option<Zones> {
    let mut is_error = false;
    let mut hosts_file_paths = Vec::from(hosts_files);
    let mut zone_file_paths = Vec::from(zone_files);

    for path in zone_dirs {
        match get_files_from_dir(path).await {
            Ok(mut paths) => zone_file_paths.append(&mut paths),
            Err(error) => {
                tracing::warn!(?path, ?error, "could not read zone directory");
                is_error = true;
            }
        }
    }
    for path in hosts_dirs {
        match get_files_from_dir(path).await {
            Ok(mut paths) => hosts_file_paths.append(&mut paths),
            Err(error) => {
                tracing::warn!(?path, ?error, "could not read hosts directory");
                is_error = true;
            }
        }
    }

    let mut combined_zones = Zones::new();
    for path in &zone_file_paths {
        match zone_from_file(Path::new(path)).await {
            Ok(Ok(zone)) => combined_zones.insert_merge(zone),
            Ok(Err(error)) => {
                tracing::warn!(?path, ?error, "could not parse zone file");
                is_error = true;
            }
            Err(error) => {
                tracing::warn!(?path, ?error, "could not read zone file");
                is_error = true;
            }
        }
    }

    let mut combined_hosts = Hosts::default();
    for path in &hosts_file_paths {
        match hosts_from_file(Path::new(path)).await {
            Ok(Ok(hosts)) => combined_hosts.merge(hosts),
            Ok(Err(error)) => {
                tracing::warn!(?path, ?error, "could not parse hosts file");
                is_error = true;
            }
            Err(error) => {
                tracing::warn!(?path, ?error, "could not read hosts file");
                is_error = true;
            }
        }
    }

    if is_error {
        None
    } else {
        combined_zones.insert_merge(combined_hosts.into());
        Some(combined_zones)
    }
}

/// Read a hosts file, for example /etc/hosts.
async fn hosts_from_file<P: AsRef<Path>>(
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
async fn zone_from_file<P: AsRef<Path>>(
    path: P,
) -> io::Result<Result<Zone, dns_types::zones::deserialise::Error>> {
    let data = read_to_string(path).await?;
    Ok(Zone::deserialise(&data))
}

/// Get files from a directory, sorted.
async fn get_files_from_dir(dir: &Path) -> io::Result<Vec<PathBuf>> {
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
