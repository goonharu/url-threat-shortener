use serde::{Deserialize, Serialize};

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
