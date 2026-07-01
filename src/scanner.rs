use std::fmt::format;

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

/// Check if the URL uses a TLD commonly associated with phishing or abuse.
/// These TLDs are flagged because of historically high abuse rates, not because every site using them is maclicious.
pub fn check_suspicious_tld(parsed: &Url) -> Option<String> {
    let suspicious_tlds = [
        ".tk", ".mk", ".ga", ".cf", ".gq", // free TLDs, heavily abused
        ".xyz", ".top", ".click", ".buzz", // cheap TLDs, common in phishing
        ".rest", ".work", ".fit", ".loan", // spam-heavy TLDs
    ];

    // Extract the host as a string, return None if no host
    let host = parsed.host_str()?;

    for tld in &suspicious_tlds {
        if host.ends_with(tld) {
            return Some(format!("Suspicious TLD detected: {}", tld));
        }
    }

    None
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

    #[test]
    fn test_suspicious_tld_flagged() {
        let url = Url::parse("http://free-money.tk/claim").unwrap();
        let result = check_suspicious_tld(&url);
        assert!(result.is_some(), "Should flag .tk TLD");
    }

    #[test]
    fn test_suspicious_tld_safe() {
        let url = Url::parse("http://example.com").unwrap();
        let result = check_suspicious_tld(&url);
        assert!(result.is_none(), "Should not flag .com TLD");
    }
}
