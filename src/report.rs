// SPDX-License-Identifier: AGPL-3.0-or-later
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub check: &'static str,
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
}

impl Finding {
    pub fn new(check: &'static str, severity: Severity, summary: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            check,
            severity,
            summary: summary.into(),
            detail: detail.into(),
        }
    }
}
