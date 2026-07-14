use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
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
        ".tk", ".ml", ".ga", ".cf", ".gq", // free TLDs, heavily abused
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

/// Check if the URL contains a '@' symbol used to disguise the real host.
/// Example: "https://google.com@evil.com" actually navigates to evil.com.
/// The part before '@' is treated as userinfo (username), which most servers ignore.
/// I'm not using URL as input because the parsed URL will correctly parse the evil.com instead
/// missing the whole point of '@' symbol.
pub fn check_at_symbol_trick(raw: &str) -> Option<String> {
    // We check the raw string, not the parsed URL, because we want to catch
    // this trick even if the URL parser normalizes it away.
    // First, strip the scheme (https://, http://) to avoid false positives
    // from "mailto:" style URIs.
    let after_scheme = if let Some(pos) = raw.find("://") {
        &raw[pos + 3..]
    } else {
        raw
    };

    // If there's an '@' before the first '/', '?' or '#', someone is using
    // the userinfo trick. Query and fragment also end the host section, so an
    // '@' inside them (e.g. "example.com?contact=me@mail.com") is not userinfo.
    let before_path = match after_scheme.find(['/', '?', '#']) {
        Some(pos) => &after_scheme[..pos],
        None => after_scheme,
    };

    if before_path.contains('@') {
        Some(format!(
            "URL contains '@' symbol - the real destination may be hidden (userinfo trick)"
        ))
    } else {
        None
    }
}

/// Check if the domain uses Punycode (xn-- prefix), which may indicate
/// a homograph attack using lookalike Unicode characters.
/// Example: "xn--pple-43d.com" renders as "apple.com" (Cyrillic 'a').
pub fn check_punycode(parsed: &Url) -> Option<String> {
    let host = parsed.host_str()?;

    // Check each label (subdomain part) for the xn-- prefix
    for label in host.split('.') {
        if label.starts_with("xn--") {
            return Some(format!(
                "Domain contains Punycode label \"{}\" - possible homograph attack",
                label
            ));
        }
    }
    None
}

/// Check if the URL is excessibely long or has too many subdomains.
/// Phishing URLs are often apdded with keywords or random strings to
/// push the real domain out of view in the browser address bar.
pub fn check_excessive_length(raw: &str, parsed: &Url) -> Option<String> {
    let mut reasons = Vec::new();

    // Flag URLs over 100 characters total
    if raw.len() > 100 {
        reasons.push(format!(
            "URL is {} characters long (threshold: 100)",
            raw.len()
        ));
    }

    // Flag domains with more than 3 subdomain levels
    // e.g. "a.b.c.d.evil.com" has 6 labels - that's suspicious
    if let Some(host) = parsed.host_str() {
        let label_count = host.split('.').count();
        if label_count > 3 {
            reasons.push(format!(
                "Domain has {} levels (e.g. \"{}\" - threshold: 3)",
                label_count, host
            ));
        }
    }

    if reasons.is_empty() {
        None
    } else {
        Some(reasons.join("; "))
    }
}

/// Load a blocklist file where each line is one known-bad domain.
/// Blank lines and lines starting with '#' are ignored.
pub fn load_blocklist(path: &Path) -> HashSet<String> {
    let content = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return HashSet::new(), // missing file = empty list, not a crash
    };

    content
        .lines()
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

/// Check if the URL's domain matches any entry in the known-bad blocklist.
/// This is signature-based detection - it catches threats but not new ones.
pub fn check_known_bad(parsed: &Url, blocklist: &HashSet<String>) -> Option<String> {
    let host = parsed.host_str()?.to_lowercase();
    let domain = host.strip_prefix("www.").unwrap_or(&host);

    if blocklist.contains(domain) {
        Some(format!(
            "Domain \"{}\" matches known-bad blocklist entry",
            domain
        ))
    } else {
        None
    }
}

/// Errors that can occur during scanning
#[derive(Debug)]
pub enum ScanError {
    InvalidUrl(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::InvalidUrl(msg) => write!(f, "Invalid URL: {}", msg),
        }
    }
}

/// Attempt to normalize a raw URL input.
/// If the user forgets the scheme (e.g. "google.com"), prepend "https://".
pub fn normalize_url(raw: &str) -> String {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return trimmed.to_string();
    }

    // Already has a scheme
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }

    // Looks like a domain (contains a dot) - prepend https://
    if trimmed.contains('.') && !trimmed.contains(' ') {
        return format!("https://{}", trimmed);
    }

    // Return as-is and let the parser give a proper error
    trimmed.to_string()
}

impl std::error::Error for ScanError {}

/// Run all heuristic checks against a URL and return a unified scan result.
///
/// This is the main entry point for the scanner module. It:
/// 1. Validates and parses the URL
/// 2. Runs every heuristic check
/// 3. Collects flags from checks that triggered
/// 4. Calculates a risk score and level based on how many checks flagged
pub fn scan_url(raw: &str, blocklist: &HashSet<String>) -> Result<ScanResult, ScanError> {
    // Normalize the input
    let normalized = normalize_url(raw);

    // Better error message for empty input
    if normalized.is_empty() {
        return Err(ScanError::InvalidUrl("URL cannot be empty".to_string()));
    }

    // Step 1: Parse the URL - fail early if it's not valid
    let parsed = Url::parse(&normalized).map_err(|_| {
        ScanError::InvalidUrl(format!(
            "\"{}\" is not a valid URL. Example: https://example.com",
            raw
        ))
    })?;

    // Step 2: Run all checks, collecting any flags
    let mut flags: Vec<String> = Vec::new();

    if let Some(flag) = check_ip_literal(&parsed) {
        flags.push(flag);
    }
    if let Some(flag) = check_suspicious_tld(&parsed) {
        flags.push(flag);
    }
    if let Some(flag) = check_typosquat(&parsed) {
        flags.push(flag);
    }
    if let Some(flag) = check_at_symbol_trick(raw) {
        flags.push(flag);
    }
    if let Some(flag) = check_punycode(&parsed) {
        flags.push(flag);
    }
    if let Some(flag) = check_excessive_length(raw, &parsed) {
        flags.push(flag);
    }
    if let Some(flag) = check_known_bad(&parsed, blocklist) {
        flags.push(flag);
    }

    // Step 3: Calculate risk based on number of flags
    let score = flags.len() as u32;
    let risk = match score {
        0 => RiskLevel::Low,
        1..=2 => RiskLevel::Medium,
        _ => RiskLevel::High,
    };

    Ok(ScanResult { risk, score, flags })
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::collections::HashSet;

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

    #[test]
    fn test_at_symbol_trick_detected() {
        let result = check_at_symbol_trick("https://google.com@evil.com/login");
        assert!(result.is_some(), "Should flag @ trick");
    }

    #[test]
    fn test_at_symbol_normal_url() {
        let result = check_at_symbol_trick("https://google.com/search?q=rust");
        assert!(result.is_none(), "Should not flag normal URL");
    }

    #[test]
    fn test_at_symbol_in_query_without_path() {
        let result = check_at_symbol_trick("https://example.com?contact=me@mail.com");
        assert!(result.is_none(), "Should not flag '@' in query string");
    }

    #[test]
    fn test_at_symbol_in_fragment_without_path() {
        let result = check_at_symbol_trick("https://example.com#user@notes");
        assert!(result.is_none(), "Should not flag '@' in fragment");
    }

    #[test]
    fn test_punycode_detected() {
        // This is "аpple.com" with a Cyrillic 'а' encoded as punycode
        let url = Url::parse("https://xn--pple-43d.com").unwrap();
        let result = check_punycode(&url);
        assert!(result.is_some(), "Should flag punycode domain");
    }

    #[test]
    fn test_punycode_normal_domain() {
        let url = Url::parse("https://apple.com").unwrap();
        let result = check_punycode(&url);
        assert!(result.is_none(), "Should not flag normal ASCII domain");
    }

    #[test]
    fn test_punycode_in_subdomain() {
        // xn--n3h decodes to ☃ (snowman emoji) — valid punycode
        let url = Url::parse("https://xn--n3h.example.com").unwrap();
        let result = check_punycode(&url);
        assert!(result.is_some(), "Should flag punycode in subdomain");
    }

    #[test]
    fn test_excessive_length_long_url() {
        let long_url = format!("https://example.com/{}", "a".repeat(200));
        let parsed = Url::parse(&long_url).unwrap();
        let result = check_excessive_length(&long_url, &parsed);
        assert!(result.is_some(), "Should flag URL over 100 chars");
    }

    #[test]
    fn test_excessive_length_many_subdomains() {
        let url_str = "https://a.b.c.d.evil.com/page";
        let parsed = Url::parse(url_str).unwrap();
        let result = check_excessive_length(url_str, &parsed);
        assert!(result.is_some(), "Should flag too many subdomains");
    }

    #[test]
    fn test_excessive_length_normal_url() {
        let url_str = "https://example.com/about";
        let parsed = Url::parse(url_str).unwrap();
        let result = check_excessive_length(url_str, &parsed);
        assert!(result.is_none(), "Should not flag short, simple URL");
    }

    #[test]
    fn test_known_bad_match() {
        let blocklist: HashSet<String> = vec![
            "evil-phishing-site.com".to_string(),
            "malware-download.net".to_string(),
        ]
        .into_iter()
        .collect();
        let url = Url::parse("https://evil-phishing-site.com/login").unwrap();
        let result = check_known_bad(&url, &blocklist);
        assert!(result.is_some(), "Should flag known-bad domain");
    }

    #[test]
    fn test_known_bad_no_match() {
        let blocklist: HashSet<String> = vec!["evil-phishing-site.com".to_string()]
            .into_iter()
            .collect();
        let url = Url::parse("https://google.com").unwrap();
        let result = check_known_bad(&url, &blocklist);
        assert!(result.is_none(), "Should not flag clean domain");
    }

    #[test]
    fn test_known_bad_empty_blocklist() {
        let blocklist: HashSet<String> = HashSet::new();
        let url = Url::parse("https://anything.com").unwrap();
        let result = check_known_bad(&url, &blocklist);
        assert!(result.is_none(), "Empty blocklist should flag nothing");
    }

    #[test]
    fn test_scan_url_clean() {
        let blocklist = HashSet::new();
        let result = scan_url("https://google.com", &blocklist).unwrap();
        assert_eq!(result.risk, RiskLevel::Low);
        assert_eq!(result.score, 0);
        assert!(result.flags.is_empty());
    }

    #[test]
    fn test_scan_url_multiple_flags() {
        // This URL should trigger: suspicious TLD + known bad
        let blocklist: HashSet<String> = vec!["evil-site.tk".to_string()].into_iter().collect();
        let result = scan_url("https://evil-site.tk/steal", &blocklist).unwrap();
        assert!(result.score >= 2, "Should flag at least TLD + known bad");
        assert_eq!(result.risk, RiskLevel::Medium);
    }

    #[test]
    fn test_scan_url_high_risk() {
        // IP literal + suspicious TLD won't combine (IP has no TLD),
        // so let's use: known bad + suspicious TLD + excessive length
        let long_path = "a".repeat(200);
        let bad_url = format!("https://evil-site.tk/{}", long_path);
        let blocklist: HashSet<String> = vec!["evil-site.tk".to_string()].into_iter().collect();
        let result = scan_url(&bad_url, &blocklist).unwrap();
        assert!(result.score >= 3, "Should flag TLD + known bad + length");
        assert_eq!(result.risk, RiskLevel::High);
    }

    #[test]
    fn test_scan_url_invalid_input() {
        let blocklist = HashSet::new();
        let result = scan_url("not a url at all", &blocklist);
        assert!(result.is_err(), "Should return error for invalid URL");
    }

    #[test]
    fn test_normalize_adds_scheme() {
        let result = normalize_url("google.com");
        assert_eq!(result, "https://google.com");
    }

    #[test]
    fn test_normalize_preserves_existing_scheme() {
        let result = normalize_url("http://example.com");
        assert_eq!(result, "http://example.com");
    }

    #[test]
    fn test_normalize_trims_whitespace() {
        let result = normalize_url("  https://example.com  ");
        assert_eq!(result, "https://example.com");
    }

    #[test]
    fn test_scan_url_empty_input() {
        let blocklist = HashSet::new();
        let result = scan_url("", &blocklist);
        assert!(result.is_err(), "Empty input should error");
    }

    #[test]
    fn test_scan_url_without_scheme() {
        let blocklist = HashSet::new();
        let result = scan_url("google.com", &blocklist);
        assert!(
            result.is_ok(),
            "Should auto-add https:// and scan successfully"
        );
    }
}
