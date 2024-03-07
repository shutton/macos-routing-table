mod route_entry;
mod routing_flag;
mod routing_table;

use std::fmt::Write;

pub use routing_table::execute_netstat;

// Exports
pub use route_entry::RouteEntry;
pub use routing_flag::RoutingFlag;
pub use routing_table::RoutingTable;

use cidr::AnyIpCidr;
use mac_address::MacAddress;

/// A generic network entity
#[derive(Debug, Clone)]
pub enum Entity {
    Default,
    Cidr(AnyIpCidr),
    Link(String),
    Mac(MacAddress),
}

impl std::fmt::Display for Entity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Entity::Default => f.write_str("default"),
            Entity::Cidr(cidr) => write!(f, "{cidr}"),
            Entity::Link(link) => f.write_str(link),
            Entity::Mac(mac) => {
                for (i, byte) in mac.bytes().iter().enumerate() {
                    if i > 0 {
                        f.write_char(':')?;
                    }
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

/// A destination entity with an optional zone
#[derive(Clone, Debug)]
pub struct Destination {
    pub entity: crate::Entity,
    pub zone: Option<String>,
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Destination { entity, zone } = self;
        write!(f, "{entity}")?;
        if let Some(zone) = &zone {
            write!(f, "%{zone}")?;
        }

        Ok(())
    }
}

/// Internet Protocols associated with routing table entries
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    V4,
    V6,
}
