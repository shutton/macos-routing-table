use crate::{Entity, Protocol, RouteEntry};
use std::{collections::HashMap, net::IpAddr, process::ExitStatus, string::FromUtf8Error};
use tokio::process::Command;

const NETSTAT_PATH: &str = "/usr/sbin/netstat";

/// A snapshot of the routing table
#[derive(Debug)]
pub struct RoutingTable {
    routes: Vec<RouteEntry>,
    /// Map of interfaces to their default routers
    if_router: HashMap<String, Vec<IpAddr>>,
}

/// Various errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to execute {NETSTAT_PATH}: {0}")]
    NetstatExec(std::io::Error),
    #[error("failed to get routing table: {0}")]
    NetstatFail(ExitStatus),
    #[error("netstat output not non-UTF-8")]
    NetstatUtf8(FromUtf8Error),
    #[error("no headers follow {0:?} section marker")]
    NetstatParseNoHeaders(String),
    #[error("parsing route entry: {0}")]
    RouteEntryParse(#[from] crate::route_entry::Error),
    #[error("route entry found before protocol (Internet/Internet6) found.")]
    EntryBeforeProto,
}

impl RoutingTable {
    /// Query the routing table using the `netstat` command.
    ///
    /// # Errors
    ///
    /// Returns an error if the `netstat` command fails to execute, or returns
    /// unparseable output.
    pub async fn load_from_netstat() -> Result<Self, Error> {
        let output = execute_netstat().await?;
        Self::from_netstat_output(&output)
    }

    /// Generate a `RoutingTable` from complete netstat output.  The output should
    /// conform to what would be returned from `netstat -rn` on macOS/Darwin.
    ///
    /// # Errors
    ///
    /// Returns an error
    pub fn from_netstat_output(output: &str) -> Result<RoutingTable, Error> {
        let mut lines = output.lines();
        let mut headers = vec![];
        let mut routes = vec![];
        let mut proto = None;
        let mut if_router = HashMap::new();

        while let Some(line) = lines.next() {
            if line.is_empty() || line.starts_with("Routing table") {
                continue;
            }
            match line {
                section @ ("Internet:" | "Internet6:") => {
                    proto = match section {
                        "Internet:" => Some(Protocol::V4),
                        "Internet6:" => Some(Protocol::V6),
                        _ => unreachable!(),
                    };
                    // Next line will contain the column headers
                    if let Some(line) = lines.next() {
                        headers = line.split_ascii_whitespace().collect();
                    } else {
                        return Err(Error::NetstatParseNoHeaders(section.into()));
                    }
                    continue;
                }
                entry => {
                    if let Some(proto) = proto {
                        let route = RouteEntry::parse(proto, entry, &headers)?;
                        if let (Entity::Default, Entity::Cidr(cidr)) =
                            (&route.dest.entity, &route.gateway.entity)
                        {
                            if cidr.is_host_address() {
                                let route = route.clone();
                                let gws = if_router.entry(route.net_if).or_insert_with(Vec::new);
                                // The route parser doesn't produce `Any` CIDRs,
                                // so there's always a first address.
                                gws.push(cidr.first_address().unwrap_or_else(|| unreachable!()));
                            }
                        }
                        routes.push(route);
                    } else {
                        return Err(Error::EntryBeforeProto);
                    }
                }
            };
        }
        Ok(RoutingTable { routes, if_router })
    }

    /// Find the routing table entry that most-precisely matches the provided
    /// address.
    #[must_use]
    pub fn find_route_entry(&self, addr: IpAddr) -> Option<&RouteEntry> {
        // TODO: implement a proper lookup table and/or short-circuit on an
        // exact match
        self.routes
            .iter()
            .filter(|route| route.contains(addr))
            .fold(None, |old, new| match old {
                None => Some(new),
                Some(old) => Some(old.most_precise(new)),
            })
    }

    #[must_use]
    pub fn default_gateways_for_netif(&self, net_if: &str) -> Option<&Vec<IpAddr>> {
        self.if_router.get(net_if)
    }
}

/// Execute `netstat -rn` and return the output
///
/// # Errors
///
/// Returns an error if command execution fails, or the output is not UTF-8
pub async fn execute_netstat() -> Result<String, Error> {
    let output = Command::new(NETSTAT_PATH)
        .arg("-rn")
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(Error::NetstatExec)?;
    if !output.status.success() {
        return Err(Error::NetstatFail(output.status));
    }
    String::from_utf8(output.stdout).map_err(Error::NetstatUtf8)
}

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::{Destination, Entity, RoutingTable};
    use std::{process::ExitStatus, string::FromUtf8Error};

    include!(concat!(env!("OUT_DIR"), "/sample_table.rs"));

    #[tokio::test]
    async fn coverage() {
        let rt = RoutingTable::from_netstat_output(SAMPLE_TABLE).expect("parse routing table");
        let _ = format!("{rt:?}");
        let _ = format!(
            "{:?}",
            Error::NetstatExec(std::io::Error::from_raw_os_error(1))
        );
        let _ = format!("{:?}", Error::NetstatFail(ExitStatus::default()));
        // This error is reachable only if the netstat command outputs invalid
        // UTF-8.
        let from_utf8err = String::from_utf8([0xa0, 0xa1].to_vec()).unwrap_err();
        let _ = format!("{:?}", Error::NetstatUtf8(from_utf8err));
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn live_test() {
        let _routing_table = RoutingTable::load_from_netstat()
            .await
            .expect("parse live routing table");
    }

    #[test]
    fn good_table() {
        let rt = RoutingTable::from_netstat_output(SAMPLE_TABLE).expect("parse routing table");
        let entry = rt.find_route_entry("1.1.1.1".parse().unwrap());
        dbg!(&entry);
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert!(matches!(
            entry.dest,
            Destination {
                entity: Entity::Default,
                zone: None
            }
        ));
        // Coverage of debug formatting
        let _ = format!("{rt:?}");
    }

    #[test]
    fn missing_headers() {
        for section in ["", "6"] {
            let input = format!("{SAMPLE_TABLE}Internet{section}:\n");
            let result = RoutingTable::from_netstat_output(&input);
            assert!(matches!(result, Err(Error::NetstatParseNoHeaders(_))));
            // Coverage of debug formatting
            let _ = format!("{:?}", result.unwrap_err());
        }
    }

    #[test]
    fn stray_entry() {
        let input = format!("extra stuff\n{SAMPLE_TABLE}");
        let result = RoutingTable::from_netstat_output(&input);
        assert!(matches!(result, Err(Error::EntryBeforeProto)));
        // Coverage of debug formatting
        let _ = format!("{:?}", result.unwrap_err());
    }

    #[test]
    fn bad_entry() {
        let input = format!("{SAMPLE_TABLE}How now brown cow.\n");
        let result = RoutingTable::from_netstat_output(&input);
        dbg!(&result);
        assert!(matches!(
            result,
            Err(Error::RouteEntryParse(
                crate::route_entry::Error::ParseIPv4AddrBadInt {
                    addr: _,
                    err: std::num::ParseIntError { .. },
                }
            ))
        ));
        // Coverage of debug formatting
        let _ = format!("{:?}", result.unwrap_err());
    }
}
