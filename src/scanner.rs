use serde::{Deserialize, Serialize};
use strsim::levenshtein;
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

/// Well-known domains to check against for typosquatting.
/// Could be bigger, if we want.
const POPULAR_DOMAINS: &[&str] = &[
    "google.com",
    "facebook.com",
    "amazon.com",
    "apple.com",
    "microsoft.com",
    "paypal.com",
    "netflix.com",
    "instagram.com",
    "twitter.com",
    "linkedin.com",
    "github.com",
    "yahoo.com",
    "chase.com",
    "wellsfargo.com",
    "bankofamerica.com",
];

/// Check if the URL's domain is suspiciously close to a well-known domain.
/// Uses levenshtein distance to detect typosquatting attempts like
/// "paypa1.com" (distance 1 from "paypal.com").
pub fn check_typosquat(parsed: &Url) -> Option<String> {
    let host = parsed.host_str()?;

    // Strip "www." prefix if present so "www.google.com" still gets checked
    let domain = host.strip_prefix("www.").unwrap_or(host);

    // Don't flag exact matches - that's the real site
    if POPULAR_DOMAINS.contains(&domain) {
        return None;
    }

    for &legit in POPULAR_DOMAINS {
        let distance = levenshtein(domain, legit);
        // Distance of 1-2 = suspiciously close but not identical
        if distance >= 1 && distance <= 2 {
            return Some(format!(
                "Possible typosquat: \"{}\" is {} edit(s) from \"{}\"",
                domain, distance, legit
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::thread::park;

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

    #[test]
    fn test_typosquat_detected() {
        let url = Url::parse("https://paypa1.com/login").unwrap();
        let result = check_typosquat(&url);
        assert!(
            result.is_some(),
            "Should flag paypa1.com as typosquat of paypal.com"
        );
    }

    #[test]
    fn test_typosquat_exact_match_not_flagged() {
        let url = Url::parse("https://paypal.com").unwrap();
        let result = check_typosquat(&url);
        assert!(result.is_none(), "Should not flag the real paypal.com");
    }

    #[test]
    fn test_typosquat_unrelated_domain() {
        let url = Url::parse("https://myblog.com").unwrap();
        let result = check_typosquat(&url);
        assert!(result.is_none(), "Should not flag unrelated domain");
    }
}
