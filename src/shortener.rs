use crate::scanner::ScanResult;
use serde::{Deserialize, Serialize};

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
