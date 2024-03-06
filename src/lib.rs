mod route_entry;
mod routing_flag;

// Exports
pub use route_entry::RouteEntry;
pub use routing_flag::RoutingFlag;

use cidr::AnyIpCidr;
use mac_address::MacAddress;
use std::{collections::HashMap, net::IpAddr, process::ExitStatus, string::FromUtf8Error};
use tokio::process::Command;

const NETSTAT_PATH: &str = "/usr/sbin/netstat";

/// A generic network entity
#[derive(Debug, Clone)]
pub enum Entity {
    Default,
    Cidr(AnyIpCidr),
    Link(String),
    Mac(MacAddress),
}

/// A destination entity with an optional zone
#[derive(Clone, Debug)]
pub struct Destination {
    pub entity: crate::Entity,
    pub zone: Option<String>,
}

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
    #[error("Unrecognized section name {0:?}")]
    NetstatParseUnrecognizedSectionName(String),
    #[error("{0:?} section missing headers")]
    NetstatParseNoHeaders(String),
    #[error("parsing route entry: {0}")]
    RouteEntryParse(#[from] route_entry::Error),
    #[error("CIDR first address neither V4 nor V6")]
    CidrNotV4V6,
    #[error("route entry found before protocol (Internet/Internet6) found.")]
    EntryBeforeProto,
}

/// Internet Protocols associated with routing table entries
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    V4,
    V6,
}

impl RoutingTable {
    /// Query the routing table using the `netstat` command.
    ///
    /// # Errors
    ///
    /// Returns an error if the `netstat` command fails to execute, or returns
    /// unparseable output.
    pub async fn load_from_netstat() -> Result<Self, Error> {
        let output = query_netstat_routing_table().await?;
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
                        _ => {
                            return Err(Error::NetstatParseUnrecognizedSectionName(section.into()))
                        }
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
                                gws.push(cidr.first_address().ok_or(Error::CidrNotV4V6)?);
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

async fn query_netstat_routing_table() -> Result<String, Error> {
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
