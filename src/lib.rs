mod entity;
mod route_entry;
mod routing_flag;

// Exports
pub use entity::Entity;
pub use route_entry::RouteEntry;
pub use routing_flag::RoutingFlag;

use anyhow::{anyhow, Result};
use std::{collections::HashMap, net::IpAddr};
use tokio::process::Command;

const NETSTAT_PATH: &str = "/usr/sbin/netstat";

/// A snapshot of the routing table
#[derive(Debug)]
pub struct RoutingTable {
    routes: Vec<RouteEntry>,
    /// Map of interfaces to their default routers
    if_router: HashMap<String, Vec<IpAddr>>,
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
    pub async fn load_from_netstat() -> Result<Self> {
        let output = query_netstat_routing_table().await?;
        Self::from_netstat_output(&output)
    }

    /// Generate a `RoutingTable` from complete netstat output.  The output should
    /// conform to what would be returned from `netstat -rn` on macOS/Darwin.
    ///
    /// # Errors
    ///
    /// Returns an error
    pub fn from_netstat_output(output: &str) -> Result<RoutingTable> {
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
                        _ => return Err(anyhow!("Unrecognized section name {proto:?}")),
                    };
                    // Next line will contain the column headers
                    if let Some(line) = lines.next() {
                        headers = line.split_ascii_whitespace().collect();
                    } else {
                        return Err(anyhow!("No headers found after {:?} section", section));
                    }
                    continue;
                }
                entry => {
                    if let Some(proto) = proto {
                        let route = RouteEntry::parse(proto, entry, &headers)?;
                        if let (Entity::Default, Entity::Cidr(cidr)) = (&route.dest, &route.gateway)
                        {
                            if cidr.is_host_address() {
                                let route = route.clone();
                                let gws = if_router.entry(route.net_if).or_insert_with(Vec::new);
                                gws.push(cidr.first_address().ok_or_else(|| {
                                    anyhow!("CIDR first address neither V4 nor V6")
                                })?);
                            }
                        }
                        routes.push(route);
                    } else {
                        return Err(anyhow!(
                            "route entry found before protocol (Internet/Internet6) found."
                        ));
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

async fn query_netstat_routing_table() -> Result<String> {
    let output = Command::new(NETSTAT_PATH)
        .arg("-rn")
        .stdin(std::process::Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        return Err(anyhow!("Failed to get routing table: {}", output.status));
    }
    String::from_utf8(output.stdout)
        .map_err(|e| anyhow!("netstat output failed UTF-8 conversion: {}", e))
}
