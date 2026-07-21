use std::net::IpAddr;

use ipnet::IpNet;

/// Maps IP prefixes to values by longest-prefix match — the cryptokey routing
/// table. Small and read-mostly, so a scan beats a trie here.
pub struct AllowedIps<T> {
    entries: Vec<(IpNet, T)>,
}

impl<T> Default for AllowedIps<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T> AllowedIps<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, net: IpNet, value: T) {
        self.entries.push((net.trunc(), value));
    }

    /// Drops every entry whose value fails the predicate. Used to remove a
    /// peer's prefixes when it is unregistered.
    pub fn retain(&mut self, keep: impl Fn(&T) -> bool) {
        self.entries.retain(|(_, value)| keep(value));
    }

    /// Returns the value whose prefix is the longest one containing `addr`.
    pub fn longest_match(&self, addr: IpAddr) -> Option<&T> {
        self.entries
            .iter()
            .filter(|(net, _)| net.contains(&addr))
            .max_by_key(|(net, _)| net.prefix_len())
            .map(|(_, value)| value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn longest_prefix_wins() {
        let mut t = AllowedIps::new();
        t.insert(net("0.0.0.0/0"), "default");
        t.insert(net("10.0.0.0/8"), "ten");
        t.insert(net("10.0.0.0/24"), "subnet");

        assert_eq!(t.longest_match(ip("10.0.0.5")), Some(&"subnet"));
        assert_eq!(t.longest_match(ip("10.1.2.3")), Some(&"ten"));
        assert_eq!(t.longest_match(ip("8.8.8.8")), Some(&"default"));
    }

    #[test]
    fn no_match_without_default() {
        let mut t = AllowedIps::new();
        t.insert(net("192.168.1.0/24"), "lan");
        assert_eq!(t.longest_match(ip("192.168.1.9")), Some(&"lan"));
        assert_eq!(t.longest_match(ip("10.0.0.1")), None);
    }

    #[test]
    fn v4_and_v6_are_independent() {
        let mut t = AllowedIps::new();
        t.insert(net("0.0.0.0/0"), "v4");
        t.insert(net("fd00::/8"), "v6");

        assert_eq!(t.longest_match(ip("1.2.3.4")), Some(&"v4"));
        assert_eq!(t.longest_match(ip("fd00::1")), Some(&"v6"));
        // a v6 address with no v6 entry does not fall through to the v4 default
        assert_eq!(t.longest_match(ip("2001:db8::1")), None);
    }

    #[test]
    fn host_prefix() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/24"), "subnet");
        t.insert(net("10.0.0.7/32"), "host");
        assert_eq!(t.longest_match(ip("10.0.0.7")), Some(&"host"));
        assert_eq!(t.longest_match(ip("10.0.0.8")), Some(&"subnet"));
    }
}
