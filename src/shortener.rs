use crate::scanner::ScanResult;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// A stored mapping from short code to original URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlMapping {
    /// The generated short code
    pub code: String,
    /// The original full URL
    pub original_url: String,
    /// Scan result at time of shortening
    pub scan_result: ScanResult,
    /// When this was created (ISO 8601 string)
    pub created_at: String,
}

/// Errors that can occur during storage operations
#[derive(Debug)]
pub enum StoreError {
    IoError(std::io::Error),
    JsonError(serde_json::Error),
    NotFound(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::IoError(e) => write!(f, "Storage I/O error: {}", e),
            StoreError::JsonError(e) => write!(f, "Storage JSON error: {}", e),
            StoreError::NotFound(code) => write!(f, "Short code \"{}\" not found", code),
        }
    }
}

impl std::error::Error for StoreError {}

/// Generate a random alphanumeric short code.
/// Uses a mix of lowercase, uppercase, and digits for URL-safe codes.
pub fn generate_code(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();

    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Load all stored URL mappings from the JSON file.
/// Returns an empty Vec if the file doesn't exist yet.
pub fn load_all(store_path: &Path) -> Result<Vec<UrlMapping>, StoreError> {
    if !store_path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(store_path).map_err(StoreError::IoError)?;

    // Handle empty file
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }

    serde_json::from_str(&content).map_err(StoreError::JsonError)
}

/// Save a new URL mapping to the JSON store.
/// Loads existing entries, appends the new one, and writes back.
pub fn save_mapping(store_path: &Path, mapping: &UrlMapping) -> Result<(), StoreError> {
    let mut entries = load_all(store_path)?;
    entries.push(mapping.clone());

    let json = serde_json::to_string_pretty(&entries).map_err(StoreError::JsonError)?;
    fs::write(store_path, json).map_err(StoreError::IoError)?;

    Ok(())
}

/// Look up a URL mapping by its short code.
pub fn resolve(store_path: &Path, code: &str) -> Result<UrlMapping, StoreError> {
    let entries = load_all(store_path)?;

    entries
        .into_iter()
        .find(|entry| entry.code == code)
        .ok_or_else(|| StoreError::NotFound(code.to_string()))
}

/// Get a timestamp string for created_at
pub fn timestamp_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();

    // Convert to rough human-readable format
    let days = secs / 86400;
    let years = 1970 + days / 365;
    let remaining_days = days % 365;
    let months = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        years, months, day, hours, minutes, seconds
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{RiskLevel, ScanResult};
    use std::fs;

    /// Helper to create a temp store file path
    fn temp_store() -> std::path::PathBuf {
        let name = format!("test_store_{}.json", generate_code(8));
        std::env::temp_dir().join(name)
    }

    #[test]
    fn test_generate_code_length() {
        let code = generate_code(6);
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_generate_code_uniqueness() {
        let code1 = generate_code(6);
        let code2 = generate_code(6);
        assert_ne!(code1, code2, "Two generated codes should differ");
    }

    #[test]
    fn test_save_and_load() {
        let path = temp_store();

        let mapping = UrlMapping {
            code: "abc123".to_string(),
            original_url: "https://example.com".to_string(),
            scan_result: ScanResult {
                risk: RiskLevel::Low,
                score: 0,
                flags: vec![],
            },
            created_at: "2026-07-01T00:00:00Z".to_string(),
        };

        save_mapping(&path, &mapping).unwrap();

        let loaded = load_all(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].code, "abc123");
        assert_eq!(loaded[0].original_url, "https://example.com");

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_resolve_found() {
        let path = temp_store();

        let mapping = UrlMapping {
            code: "xyz789".to_string(),
            original_url: "https://rust-lang.org".to_string(),
            scan_result: ScanResult {
                risk: RiskLevel::Low,
                score: 0,
                flags: vec![],
            },
            created_at: "2026-07-01T00:00:00Z".to_string(),
        };

        save_mapping(&path, &mapping).unwrap();

        let result = resolve(&path, "xyz789").unwrap();
        assert_eq!(result.original_url, "https://rust-lang.org");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_resolve_not_found() {
        let path = temp_store();
        let result = resolve(&path, "doesnotexist");
        assert!(result.is_err(), "Should error on missing code");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let path = Path::new("/tmp/this_file_does_not_exist_ever.json");
        let result = load_all(path).unwrap();
        assert!(result.is_empty(), "Missing file should return empty Vec");
    }
}
