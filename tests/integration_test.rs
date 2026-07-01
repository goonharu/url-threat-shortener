use std::collections::HashSet;
use std::path::Path;
use url_threat_shortener::scanner::{RiskLevel, load_blocklist, scan_url};
use url_threat_shortener::shortener::{
    UrlMapping, generate_code, resolve, save_mapping, timestamp_now,
};

// ─── Scanner Integration Tests ───

#[test]
fn test_full_scan_clean_url() {
    let blocklist = HashSet::new();
    let result = scan_url("https://google.com", &blocklist).unwrap();
    assert_eq!(result.risk, RiskLevel::Low);
    assert_eq!(result.score, 0);
}

#[test]
fn test_full_scan_multiple_flags() {
    let blocklist: HashSet<String> = vec!["evil-site.tk".to_string()].into_iter().collect();

    let result = scan_url("https://evil-site.tk/phish", &blocklist).unwrap();
    assert!(result.score >= 2, "Should catch TLD + blocklist");
    assert!(result.flags.iter().any(|f| f.contains("Suspicious TLD")));
    assert!(result.flags.iter().any(|f| f.contains("known-bad")));
}

#[test]
fn test_full_scan_ip_literal() {
    let blocklist = HashSet::new();
    let result = scan_url("http://192.168.1.1/admin", &blocklist).unwrap();
    assert!(result.score >= 1);
    assert!(result.flags.iter().any(|f| f.contains("IPv4")));
}

#[test]
fn test_full_scan_at_trick() {
    let blocklist = HashSet::new();
    let result = scan_url("https://google.com@evil.com/steal", &blocklist).unwrap();
    assert!(result.flags.iter().any(|f| f.contains("@")));
}

#[test]
fn test_full_scan_auto_normalize() {
    let blocklist = HashSet::new();
    // No scheme — should auto-add https:// and scan
    let result = scan_url("example.com", &blocklist);
    assert!(result.is_ok(), "Should handle missing scheme gracefully");
}

#[test]
fn test_full_scan_invalid_input() {
    let blocklist = HashSet::new();
    let result = scan_url("not a url at all", &blocklist);
    assert!(result.is_err());
}

#[test]
fn test_full_scan_empty_input() {
    let blocklist = HashSet::new();
    let result = scan_url("", &blocklist);
    assert!(result.is_err());
}

// ─── Blocklist Integration Tests ───

#[test]
fn test_load_blocklist_missing_file() {
    let list = load_blocklist(Path::new("nonexistent_file.txt"));
    assert!(list.is_empty());
}

// ─── Shortener Integration Tests ───

#[test]
fn test_shorten_resolve_roundtrip() {
    let store_path = std::env::temp_dir().join(format!("test_int_{}.json", generate_code(8)));

    let blocklist = HashSet::new();
    let scan_result = scan_url("https://example.com", &blocklist).unwrap();

    let code = generate_code(6);
    let mapping = UrlMapping {
        code: code.clone(),
        original_url: "https://example.com".to_string(),
        scan_result,
        created_at: timestamp_now(),
    };

    save_mapping(&store_path, &mapping).unwrap();

    let resolved = resolve(&store_path, &code).unwrap();
    assert_eq!(resolved.original_url, "https://example.com");
    assert_eq!(resolved.scan_result.risk, RiskLevel::Low);

    let _ = std::fs::remove_file(&store_path);
}

#[test]
fn test_resolve_nonexistent_code() {
    let store_path = std::env::temp_dir().join(format!("test_int_{}.json", generate_code(8)));
    let result = resolve(&store_path, "doesnotexist");
    assert!(result.is_err());
}

#[test]
fn test_multiple_mappings() {
    let store_path = std::env::temp_dir().join(format!("test_int_{}.json", generate_code(8)));
    let blocklist = HashSet::new();

    // Store two different URLs
    for url in &["https://example.com", "https://rust-lang.org"] {
        let scan_result = scan_url(url, &blocklist).unwrap();
        let mapping = UrlMapping {
            code: generate_code(6),
            original_url: url.to_string(),
            scan_result,
            created_at: timestamp_now(),
        };
        save_mapping(&store_path, &mapping).unwrap();
    }

    // Both should be retrievable
    let all = url_threat_shortener::shortener::load_all(&store_path).unwrap();
    assert_eq!(all.len(), 2);

    let _ = std::fs::remove_file(&store_path);
}
