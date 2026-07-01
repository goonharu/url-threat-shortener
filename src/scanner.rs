use serde::{Deserialize, Serialize};
use url::Url;

/// Risk level assigned after scanning a URL
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Result of scanning a single URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Overall risk level
    pub risk: RiskLevel,
    /// Numeric score - number of heuristics that flagged
    pub score: u32,
    /// Human-readable reasons for each flag
    pub flags: Vec<String>,
}

/// Check if the URL uses a raw IP address instead of a domain name
/// Phishing and malware sites often use IP literals to avoid domain-based blocklists
pub fn check_ip_literal(parsed: &Url) -> Option<String> {
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => Some(format!("URL uses raw IPv4 address: {}", ip)),
        Some(url::Host::Ipv6(ip)) => Some(format!("URL uses raw IPv6 address: {}", ip)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_literal_ipv4() {
        let url = Url::parse("http://192.168.1.1/login").unwrap();
        let result = check_ip_literal(&url);
        assert!(result.is_some(), "Should flag IPv4 literal");
    }

    #[test]
    fn test_ip_literal_normal_domain() {
        let url = Url::parse("http://google.com").unwrap();
        let result = check_ip_literal(&url);
        assert!(result.is_none(), "Should not flag normal domain");
    }
}
