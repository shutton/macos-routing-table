use crate::{Entity, Protocol, RoutingFlag};
use anyhow::{anyhow, Result};
use cidr::AnyIpCidr;
use mac_address::MacAddress;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

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

impl RouteEntry {
    pub(crate) fn parse(proto: Protocol, line: &str, headers: &[&str]) -> Result<Self> {
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
            dest_zone,
            gateway,
            gw_zone,
            flags,
            net_if,
            expires,
        };
        Ok(route)
    }
    /// Return whether the specified route's destination is appropriate for the given address
    pub(crate) fn contains(&self, addr: IpAddr) -> bool {
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
                Entity::Default => false,
            },
            _ => false,
        }
    }

    /// Compare two routes, returning the one that is more-precise based on whether
    /// it resolves to an identified device or interface, or has a larger network
    /// length
    pub(crate) fn most_precise<'a>(&'a self, other: &'a Self) -> &'a Self {
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
        let zone = zone_etc.next().map(ToOwned::to_owned);

        if let Some(bits) = zone_etc.next() {
            // Just reassemble it without the %zone and run it through the regular parser
            let s = format!("{addr}{bits}");
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
            if let Ok(ipv4addr) = parse_ipv4dest(addr) {
                Entity::Cidr(AnyIpCidr::new_host(IpAddr::V4(ipv4addr)))
            } else {
                // Bridge broadcast addresses sometimes contain a dot-delimited MAC address
                Entity::Mac(addr.replace('.', ":").parse::<MacAddress>()?)
            }
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

fn parse_flags(flags_s: &str) -> HashSet<RoutingFlag> {
    flags_s.chars().map(RoutingFlag::from).collect()
}

fn parse_expire(s: &str) -> Result<Option<Duration>> {
    match s {
        "!" => Ok(None),
        n => Ok(Some(Duration::from_secs(n.parse()?))),
    }
}

fn parse_ipv4dest(dest: &str) -> Result<Ipv4Addr> {
    dest.parse::<Ipv4Addr>()
        .or_else(|_| {
            let parts: Vec<u8> = dest
                .split('.')
                .map(str::parse)
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
