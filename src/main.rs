// SPDX-License-Identifier: AGPL-3.0-or-later
mod checks;
mod report;

use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Serialize;
use tracing::{debug, info, warn};

use checks::all_checks;
use report::{Coverage, CoverageStatus, Finding, Severity};

#[derive(Parser)]
#[command(name = "hunter", version, about = "Linux compromise detection platform: has this host been hacked, and how?")]
struct Cli {
    /// Drop the running narration (every file read, every process inspected) and
    /// show only warnings and findings. Maximum verbosity is the default: this
    /// tool is built to be read, not trusted blindly, so showing its work is the
    /// point. RUST_LOG still overrides both.
    #[arg(long, short, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run every check once and print the findings.
    Scan {
        /// Emit findings as JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Run checks on a repeating interval (the daemon's normal mode).
    Watch {
        /// Seconds between scan passes.
        #[arg(long, default_value_t = 300)]
        interval: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let default_level = if cli.quiet { "warn" } else { "debug" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(format!("hunter={default_level}").parse()?),
        )
        .init();

    match cli.command.unwrap_or(Command::Watch { interval: 300 }) {
        Command::Scan { json } => {
            let report = run_all_checks();
            print_report(&report, json);
        }
        Command::Watch { interval } => {
            run_watch_loop(interval).await?;
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct Report {
    findings: Vec<Finding>,
    coverage: Vec<Coverage>,
    /// A always-hedged, scope-limited summary of what this report does and
    /// does not establish. Computed fresh every run from the actual
    /// coverage data below, specifically so nothing (a renderer, a
    /// downstream consumer, an empty findings list) can present a scan as
    /// an unconditional clean bill of health. See `build_statement`.
    statement: String,
}

fn run_all_checks() -> Report {
    let mut findings = Vec::new();
    let mut coverage = Vec::new();

    for check in all_checks() {
        debug!(check = check.name(), "starting check");
        match check.run() {
            Ok(mut output) => {
                debug!(check = check.name(), findings = output.findings.len(), skipped = output.skipped.len(), "check complete");
                let status = if output.skipped.is_empty() { CoverageStatus::Ran } else { CoverageStatus::Partial };
                coverage.push(Coverage {
                    check: check.name(),
                    status,
                    detail: output.skipped.join("; "),
                });
                findings.append(&mut output.findings);
            }
            Err(err) => {
                warn!(check = check.name(), error = %err, "check failed to run");
                coverage.push(Coverage {
                    check: check.name(),
                    status: CoverageStatus::Failed,
                    detail: err.to_string(),
                });
            }
        }
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let statement = build_statement(&findings, &coverage);
    Report { findings, coverage, statement }
}

/// Builds a scope-limited summary that can never read as an unconditional
/// "clean" verdict, however the findings/coverage turn out. A platform
/// this tool was explicitly asked to never claim: kernel compromise,
/// firmware/boot tampering, and memory-resident code outside what the
/// implemented checks look at are never ruled out by a passing scan --
/// `hunter` is Phase 1 (live userland/filesystem triage) of a larger
/// design (docs/SPEC.md), not an attestation system, and every check it
/// runs is still mediated by the host's own kernel (CLAUDE.md rule #1
/// reduces *tampering risk* in how we collect evidence; it does not
/// bypass a compromised kernel, which could still misreport what this
/// process observes).
fn build_statement(findings: &[Finding], coverage: &[Coverage]) -> String {
    let total = coverage.len();
    let complete = coverage.iter().filter(|c| c.status == CoverageStatus::Ran).count();
    let incomplete: Vec<&str> = coverage.iter().filter(|c| c.status != CoverageStatus::Ran).map(|c| c.check).collect();

    let coverage_clause = if incomplete.is_empty() {
        format!("all {total} implemented checks completed with full coverage")
    } else {
        format!("{complete} of {total} implemented checks completed with full coverage ({} partial or failed: {})", incomplete.len(), incomplete.join(", "))
    };

    let findings_clause = if findings.is_empty() {
        "no anomalies were reported by the checks that ran".to_string()
    } else {
        format!("{} finding(s) were reported and need human review", findings.len())
    };

    format!(
        "{coverage_clause}; {findings_clause}. This does NOT establish the host is free of \
         compromise: every check here reads through the host's own kernel (a compromised \
         kernel could misreport what's observed), covers only userland/filesystem artifacts \
         implemented so far, and has no package-hash baseline, kernel/memory verification, \
         boot/firmware attestation, or external corroboration behind it yet. See CLAUDE.md's \
         \"Current implementation status\" for exactly what is and isn't covered."
    )
}

fn print_report(report: &Report, json: bool) {
    if json {
        // serde_json escapes control characters ( etc.) as part of
        // normal JSON string syntax, so this path is already safe without
        // sanitize_for_terminal -- and preserving the raw bytes here,
        // unlike the text path below, is the point (EV-04: preserve raw
        // evidence; a consumer parsing this JSON should see exactly what
        // was on disk, not a human-readability transform).
        println!("{}", serde_json::to_string_pretty(report).unwrap_or_default());
        return;
    }

    // Finding summaries/details embed raw filenames and, in some checks,
    // raw config-file line text -- both are attacker- or unprivileged-
    // user-controlled in general (anything under a scanned home directory,
    // for instance). Printed unescaped to a real terminal, a crafted
    // filename containing ANSI escapes could reposition the cursor, hide
    // or rewrite displayed text, or change the window title -- a local
    // user attacking whoever reviews a root-run scan's output. Sanitized
    // here, at the presentation boundary, rather than in every check that
    // constructs a Finding, so nothing has to remember to do this itself.
    if report.findings.is_empty() {
        println!("No findings.");
    } else {
        for finding in &report.findings {
            println!("[{}] ({}) {}", finding.severity, finding.check, sanitize_for_terminal(&finding.summary));
            println!("    {}\n", sanitize_for_terminal(&finding.detail).replace('\n', "\n    "));
        }
        println!("{} finding(s).", report.findings.len());
    }

    println!("\nCoverage:");
    for entry in &report.coverage {
        let marker = match entry.status {
            CoverageStatus::Ran => "ok",
            CoverageStatus::Partial => "PARTIAL",
            CoverageStatus::Failed => "FAILED",
        };
        println!("  [{marker}] {}", entry.check);
        if !entry.detail.is_empty() {
            println!("      {}", sanitize_for_terminal(&entry.detail));
        }
    }

    println!("\n{}", sanitize_for_terminal(&report.statement));
}

/// Escapes control characters (the C0 set including ESC/CR, DEL, and the
/// C1 set) to their visible `\u{..}` form so untrusted text embedded in a
/// finding can't manipulate the terminal it's printed to. Newlines and
/// tabs pass through unescaped since findings legitimately use them for
/// readability (e.g. multi-line file contents in a detail string).
fn sanitize_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() && c != '\n' && c != '\t' {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use report::CoverageStatus;

    #[test]
    fn statement_never_claims_clean_even_with_zero_findings_and_full_coverage() {
        // The exact "false-clean" shape this exists to prevent: no
        // findings, every check fully ran. The statement must still say
        // this doesn't establish the host is clean.
        let coverage = vec![Coverage { check: "processes", status: CoverageStatus::Ran, detail: String::new() }];
        let statement = build_statement(&[], &coverage);
        assert!(statement.contains("does NOT establish"), "statement: {statement}");
        assert!(statement.contains("all 1 implemented checks completed"), "statement: {statement}");
    }

    #[test]
    fn statement_names_which_checks_are_incomplete() {
        let coverage = vec![
            Coverage { check: "processes", status: CoverageStatus::Ran, detail: String::new() },
            Coverage { check: "network", status: CoverageStatus::Partial, detail: "some pids denied".to_string() },
            Coverage { check: "accounts", status: CoverageStatus::Failed, detail: "boom".to_string() },
        ];
        let statement = build_statement(&[], &coverage);
        assert!(statement.contains("1 of 3"), "statement: {statement}");
        assert!(statement.contains("network"), "statement: {statement}");
        assert!(statement.contains("accounts"), "statement: {statement}");
    }

    #[test]
    fn statement_reports_finding_count_when_present() {
        let coverage = vec![Coverage { check: "pam", status: CoverageStatus::Ran, detail: String::new() }];
        let findings = vec![Finding::new("pam", Severity::High, "test finding", "detail")];
        let statement = build_statement(&findings, &coverage);
        assert!(statement.contains("1 finding(s) were reported"), "statement: {statement}");
    }

    #[test]
    fn sanitize_escapes_ansi_and_other_control_chars() {
        let hostile = "normal\x1b[2J\x1b[31mFAKE CRITICAL FINDING\x1b[0m\rtext";
        let clean = sanitize_for_terminal(hostile);
        assert!(!clean.contains('\x1b'), "raw ESC must not survive: {clean:?}");
        assert!(!clean.contains('\r'), "raw CR must not survive: {clean:?}");
        assert!(clean.contains("\\u{1b}"), "escaped form should be visible: {clean:?}");
    }

    #[test]
    fn sanitize_preserves_newlines_and_tabs() {
        let text = "line one\n\tindented line two";
        assert_eq!(sanitize_for_terminal(text), text);
    }

    #[test]
    fn sanitize_leaves_ordinary_text_untouched() {
        let text = "pid 1234 is executing out of /tmp, exe: /tmp/evil (deleted)";
        assert_eq!(sanitize_for_terminal(text), text);
    }
}

async fn run_watch_loop(interval_secs: u64) -> Result<()> {
    info!(interval_secs, "starting watch loop");
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let report = run_all_checks();
                for finding in &report.findings {
                    match finding.severity {
                        Severity::Critical | Severity::High => {
                            tracing::error!(check = finding.check, summary = %finding.summary, detail = %finding.detail, "finding");
                        }
                        Severity::Medium => {
                            warn!(check = finding.check, summary = %finding.summary, "finding");
                        }
                        Severity::Low | Severity::Info => {
                            info!(check = finding.check, summary = %finding.summary, "finding");
                        }
                    }
                }
                for entry in &report.coverage {
                    match entry.status {
                        CoverageStatus::Ran => debug!(check = entry.check, "full coverage this pass"),
                        CoverageStatus::Partial => warn!(check = entry.check, detail = %entry.detail, "partial coverage this pass"),
                        CoverageStatus::Failed => tracing::error!(check = entry.check, detail = %entry.detail, "check failed this pass"),
                    }
                }
                if report.findings.is_empty() {
                    info!("scan pass complete, no findings");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal, exiting");
                return Ok(());
            }
        }
    }
}
