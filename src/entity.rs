use cidr::AnyIpCidr;
use mac_address::MacAddress;

/// A generic network entity representing either a destination or gateway
#[derive(Debug, Clone)]
pub enum Entity {
    Default,
    Cidr(AnyIpCidr),
    Link(String),
    Mac(MacAddress),
}
