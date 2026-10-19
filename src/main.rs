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
    Report { findings, coverage }
}

fn print_report(report: &Report, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(report).unwrap_or_default());
        return;
    }

    if report.findings.is_empty() {
        println!("No findings.");
    } else {
        for finding in &report.findings {
            println!("[{}] ({}) {}", finding.severity, finding.check, finding.summary);
            println!("    {}\n", finding.detail.replace('\n', "\n    "));
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
            println!("      {}", entry.detail);
        }
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
