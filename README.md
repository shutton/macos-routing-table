# macos-routing-table

A basic parser and route testing API for macOS devices.  Parses a static or live routing table (via the `netstat` command) and provides an interface to inspect tht table, and to determine which gateway and interface would be used to route traffic to a given address.

Analyzes both the IPv4 and IPv6 routing tables. Minimal support for zones (parsing only at this time).

## Example - find the gateway for an address

``` rust
use anyhow::Result;
use macos_routing_table::{RouteEntry, RoutingTable};

#[tokio::main]
async fn main() -> Result<()> {
    let rt = RoutingTable::load_from_netstat().await?;
    let addr = "1.1.1.1".parse()?;

    if let Some(RouteEntry {
        net_if, gateway, ..
    }) = rt.find_route_entry(addr)
    {
        println!("{addr:?} => {gateway} via {net_if}");
    } else {
        println!("No route to {addr:?}");
    }

    Ok(())
}
```
