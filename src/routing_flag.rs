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
