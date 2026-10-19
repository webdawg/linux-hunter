// SPDX-License-Identifier: AGPL-3.0-or-later
mod checks;
mod report;

use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, warn};

use checks::all_checks;
use report::{Finding, Severity};

#[derive(Parser)]
#[command(name = "linux-defensed", version, about = "Continuous compromise-detection daemon for Linux hosts")]
struct Cli {
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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("linux_defensed=info".parse()?))
        .init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Watch { interval: 300 }) {
        Command::Scan { json } => {
            let findings = run_all_checks();
            print_report(&findings, json);
        }
        Command::Watch { interval } => {
            run_watch_loop(interval).await?;
        }
    }

    Ok(())
}

fn run_all_checks() -> Vec<Finding> {
    let mut findings = Vec::new();
    for check in all_checks() {
        match check.run() {
            Ok(mut f) => findings.append(&mut f),
            Err(err) => warn!(check = check.name(), error = %err, "check failed to run"),
        }
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings
}

fn print_report(findings: &[Finding], json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(findings).unwrap_or_default());
        return;
    }

    if findings.is_empty() {
        println!("No findings.");
        return;
    }

    for finding in findings {
        println!("[{}] ({}) {}", finding.severity, finding.check, finding.summary);
        println!("    {}\n", finding.detail.replace('\n', "\n    "));
    }
    println!("{} finding(s).", findings.len());
}

async fn run_watch_loop(interval_secs: u64) -> Result<()> {
    info!(interval_secs, "starting watch loop");
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let findings = run_all_checks();
                for finding in &findings {
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
                if findings.is_empty() {
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
