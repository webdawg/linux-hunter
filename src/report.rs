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

/// What a `Check` produced, split from `Finding` so a check can be honest about
/// parts of itself it could not run (CLAUDE.md rule #8: never let "not checked"
/// read as "clean"). `skipped` holds one human-readable reason per gap, e.g.
/// "23 of 180 pids: permission denied reading /proc/<pid>/exe (needs root)".
#[derive(Debug, Default)]
pub struct CheckOutput {
    pub findings: Vec<Finding>,
    pub skipped: Vec<String>,
}

impl CheckOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn skip(&mut self, reason: impl Into<String>) {
        self.skipped.push(reason.into());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageStatus {
    /// The check ran to completion with nothing it couldn't inspect.
    Ran,
    /// The check ran, but part of it could not be inspected (see detail).
    Partial,
    /// The check did not run at all.
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub check: &'static str,
    pub status: CoverageStatus,
    pub detail: String,
}
