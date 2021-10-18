use anyhow::{anyhow, Result};
use cidr::AnyIpCidr;
use futures::future::BoxFuture;
use mac_address::MacAddress;
use std::collections::{HashSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

/// A snapshot of the routing table
#[derive(Debug)]
pub struct RoutingTable {
    routes: Vec<RouteEntry>,
    // Map of interfaces to their default routers
    if_router: HashMap<String, Vec<IpAddr>>,
}

/// Internet Protocols
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    V4,
    V6,
}

/// A single route obtained from the `netstat -rn` output
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Protocol
    pub proto: Protocol,

    /// Destination.  E.g., a host or CIDR
    pub dest: Entity,

    /// Destination's zone qualifer (primarily for IPv6)
    pub dest_zone: Option<String>,

    /// Gateway (i.e., how to reach the destination)
    pub gateway: Entity,

    /// Gateway's zone (primarily for IPv6)
    pub gw_zone: Option<String>,

    /// Routing flags
    pub flags: HashSet<RoutingFlag>,

    /// Network interface that holds this route
    pub net_if: String,

    /// RouteEntry expiration.  This is primarily seen for ARP-derived entries
    pub expires: Option<Duration>,
}

/// A generic network entity representing either a destination or gateway
#[derive(Debug, Clone)]
pub enum Entity {
    Default,
    Cidr(AnyIpCidr),
    Link(String),
    Mac(MacAddress),
}

#[allow(dead_code)]
#[derive(Clone, Debug, std::hash::Hash, Eq, PartialEq)]
pub enum RoutingFlag {
    Proto1,    // 1
    Proto2,    // 2
    Proto3,    // 3
    Blackhole, // B
    Broadcast, // b
    Cloning,   // C
    PrCloning, // c
    Dynamic,   // D
    Gateway,   // G
    Host,      // H
    IfScope,   // I
    IfRef,     // i
    LlInfo,    // L
    Modified,  // M
    Multicast, // m
    Reject,    // R
    Router,    // r
    Static,    // S
    Up,        // U
    WasCloned, // W
    XResolve,  // X
    Proxy,     // Y
    Global,    // g
    Unknown,
}

async fn query_netstat_routing_table() -> Result<String> {
    let output = Command::new("/usr/sbin/netstat")
        .arg("-rn")
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        return Err(anyhow!("Failed to get routing table: {}", output.status));
    }
    String::from_utf8(output.stdout)
        .map_err(|e| anyhow!("netstat output failed UTF-8 conversion: {}", e))
}

impl RoutingTable {
    /// Query the routing table using the `netstat` command.  Returns a future
    /// which must be `await`ed.
    pub fn load_from_netstat() -> BoxFuture<'static, Result<Self>> {
        Box::pin(async move {
            let output = query_netstat_routing_table().await?;
            Self::from_netstat_output(&output)
        })
    }

    /// Generate a RoutingTable from complete netstat output.  The output should
    /// conform to what would be returned from `netstat -rn` on macOS/Darwin.
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
                        _ => unreachable!(),
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
                        let route = parse_route(proto, entry, &headers)?;
                        if let (Entity::Default, Entity::Cidr(cidr)) = (&route.dest, &route.gateway) {
                            if cidr.is_host_address() {
                                let route = route.clone();
                                let gws = if_router.entry(route.net_if).or_insert_with(Vec::new);
                                gws.push(cidr.first_address().unwrap());
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

    pub fn find_route_entry(&self, addr: IpAddr) -> Option<&RouteEntry> {
        self.routes
            .iter()
            .filter(|route| route.contains(addr))
            .fold(None, |old, new| match old {
                None => Some(new),
                Some(old) => Some(old.most_precise(new)),
            })
    }

    /// Return the gateway and interface that would likely handle packets intended
    /// for the specified address.
    pub fn find_gateway(&self, addr: IpAddr) -> Option<(&Entity, &str)> {
        self.find_route_entry(addr)
            .map(|route| (&route.gateway, route.net_if.as_str()))
    }

    /// Return the interface that would likely handle packets intended
    /// for the specified address.
    pub fn find_gateway_netif(&self, addr: IpAddr) -> Option<&str> {
        self.find_route_entry(addr)
            .map(|route| route.net_if.as_str())
    }
    
    pub fn default_gateways_for_netif(&self, net_if: &str) -> Option<&Vec<IpAddr>> {
        self.if_router.get(net_if)
    }
}

impl RouteEntry {
    /// Return whether the specified route's destination is appropriate for the given address
    fn contains(&self, addr: IpAddr) -> bool {
        match self.dest {
            Entity::Cidr(cidr) => cidr.contains(&addr),
            Entity::Default => match self.gateway {
                Entity::Cidr(_) => match addr {
                    IpAddr::V4(_) => matches!(self.proto, Protocol::V4),
                    // FIXME: IPv6 should take zone into account
                    IpAddr::V6(_) => matches!(self.proto, Protocol::V6),
                },
                // These seem unlikely, but assume they're good if found
                Entity::Link(_) | Entity::Mac(_) => true,
                // Anything else is probably bad
                _ => false,
            },
            _ => false,
        }
    }

    /// Compare two routes, returning the one that is more-precise based on whether
    /// it resolves to an identified device or interface, or has a larger network
    /// length
    fn most_precise<'a>(&'a self, other: &'a Self) -> &'a Self {
        match self.dest {
            // If this is a hardware address, we already know it's on the same local network, and it's in the ARP table
            Entity::Mac(_) => self,
            Entity::Link(_) => match other.dest {
                // The other specifies a hardware address -- it's better
                Entity::Mac(_) => other,
                // Otherwise, just default to the LHS
                _ => self,
            },
            Entity::Cidr(cidr) => match other.dest {
                Entity::Mac(_) | Entity::Link(_) => other,
                Entity::Cidr(other_cidr) => {
                    if let Some(cidr_nl) = cidr.network_length() {
                        if let Some(other_nl) = other_cidr.network_length() {
                            if cidr_nl >= other_nl {
                                self
                            } else {
                                other
                            }
                        } else {
                            panic!("Can't compare gateway CIDR of 'Any' type");
                        }
                    } else {
                        panic!("Can't complare gateway CIDR of 'Any' type");
                    }
                }
                Entity::Default => self,
            },
            Entity::Default => match other.dest {
                Entity::Default => self,
                _ => other,
            },
        }
    }
}

fn parse_route(proto: Protocol, line: &str, headers: &[&str]) -> Result<RouteEntry> {
    let fields: Vec<String> = line.split_ascii_whitespace().map(str::to_string).collect();
    let mut flags = HashSet::new();
    let mut dest_and_zone: Option<(Entity, Option<String>)> = None;
    let mut gw_and_zone: Option<(Entity, Option<String>)> = None;
    let mut net_if: Option<String> = None;
    let mut expires = None;

    // Scan through the fields, matching them up with the headers.
    for (header, field) in headers.iter().zip(fields) {
        match *header {
            "Destination" => dest_and_zone = Some(parse_destination(&field)?),
            "Gateway" => gw_and_zone = Some(parse_destination(&field)?),
            "Flags" => flags = parse_flags(&field),
            "Netif" => net_if = Some(field),
            "Expire" => expires = parse_expire(&field)?,
            _ => (),
        }
    }
    let (dest, dest_zone) = dest_and_zone.ok_or_else(|| anyhow!("No destination found"))?;
    let (gateway, gw_zone) = gw_and_zone.ok_or_else(|| anyhow!("No gateway found"))?;
    let net_if = net_if.ok_or_else(|| anyhow!("No network interface found"))?;

    let route = RouteEntry {
        proto,
        dest,
        flags,
        gateway,
        net_if,
        dest_zone,
        gw_zone,
        expires,
    };
    Ok(route)
}

fn parse_destination(dest: &str) -> Result<(Entity, Option<String>)> {
    if dest.starts_with("link") {
        return Ok((Entity::Link(dest.to_owned()), None));
    }
    Ok(if let Some(pos) = dest.find('%') {
        // This route contains a zone ID
        // See: https://superuser.com/questions/99746/why-is-there-a-percent-sign-in-the-ipv6-address
        let (addr, zone_etc) = dest.split_at(pos);
        let addr: AnyIpCidr = addr.parse()?;
        let mut zone_etc = zone_etc.split('/');
        let zone = zone_etc.next().map(|s| s.to_owned());

        if let Some(bits) = zone_etc.next() {
            // Just reassemble it without the %zone and run it through the regular parser
            let s = format!("{}{}", addr, bits);
            (parse_simple_destination(&s)?, zone)
        } else {
            (Entity::Cidr(addr), zone)
        }
    } else {
        (parse_simple_destination(dest)?, None)
    })
}

fn parse_simple_destination(dest: &str) -> Result<Entity> {
    Ok(match dest {
        "default" => Entity::Default,

        cidr if cidr.contains('/') => Entity::Cidr(cidr.parse()?),
        // IPv4 host
        addr if addr.contains('.') => {
            Entity::Cidr(AnyIpCidr::new_host(IpAddr::V4(parse_ipv4dest(addr)?)))
        }
        // IPv6 host
        addr if addr.contains(':') => {
            if let Ok(v6addr) = addr.parse::<Ipv6Addr>() {
                Entity::Cidr(AnyIpCidr::new_host(IpAddr::V6(v6addr)))
            } else {
                // Try as a MAC address
                Entity::Mac(addr.parse::<MacAddress>()?)
            }
        }
        // Match bare numbers
        num => Entity::Cidr(AnyIpCidr::new_host(IpAddr::V4(parse_ipv4dest(num)?))),
    })
}

fn parse_ipv4dest(dest: &str) -> Result<Ipv4Addr> {
    dest.parse::<Ipv4Addr>()
        .or_else(|_| {
            let parts: Vec<u8> = dest
                .split('.')
                .map(|s| s.parse::<u8>())
                .collect::<std::result::Result<Vec<u8>, std::num::ParseIntError>>()?;
            // This bizarre byte-ordering comes from inet_addr(3)
            match parts.len() {
                3 => Ok(Ipv4Addr::new(parts[0], parts[1], 0, parts[2])),
                2 => Ok(Ipv4Addr::new(parts[0], 0, 0, parts[1])),
                1 => Ok(Ipv4Addr::new(0, 0, 0, parts[0])),
                len => Err(anyhow!(
                    "Invalid number of IPv4 address components ({}) in {:?}",
                    len,
                    dest
                )),
            }
        })
        .map_err(|e| anyhow!("Unable to parse {:?} as IpAddr: {}", dest, e))
}

impl From<char> for RoutingFlag {
    fn from(flag_c: char) -> Self {
        match flag_c {
            '1' => RoutingFlag::Proto1,
            '2' => RoutingFlag::Proto2,
            '3' => RoutingFlag::Proto3,
            'B' => RoutingFlag::Blackhole,
            'C' => RoutingFlag::Cloning,
            'D' => RoutingFlag::Dynamic,
            'G' => RoutingFlag::Gateway,
            'H' => RoutingFlag::Host,
            'I' => RoutingFlag::IfScope,
            'L' => RoutingFlag::LlInfo,
            'M' => RoutingFlag::Modified,
            'R' => RoutingFlag::Reject,
            'S' => RoutingFlag::Static,
            'U' => RoutingFlag::Up,
            'W' => RoutingFlag::WasCloned,
            'X' => RoutingFlag::XResolve,
            'Y' => RoutingFlag::Proxy,
            'b' => RoutingFlag::Broadcast,
            'c' => RoutingFlag::PrCloning,
            'g' => RoutingFlag::Global,
            'i' => RoutingFlag::IfRef,
            'm' => RoutingFlag::Multicast,
            'r' => RoutingFlag::Router,
            _ => RoutingFlag::Unknown,
        }
    }
}

fn parse_flags(flags_s: &str) -> HashSet<RoutingFlag> {
    flags_s.chars().map(RoutingFlag::from).collect()
}

fn parse_expire(s: &str) -> Result<Option<Duration>> {
    match s {
        "!" => Ok(None),
        n => Ok(Some(Duration::from_secs(n.parse()?))),
    }
}
