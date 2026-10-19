// SPDX-License-Identifier: AGPL-3.0-or-later
pub mod accounts;
pub mod network;
pub mod persistence;
pub mod processes;

use crate::report::CheckOutput;
use anyhow::Result;

/// A single category of compromise indicator. Each check inspects one
/// corner of the system and returns whatever it finds suspicious, plus
/// an honest account of anything it couldn't inspect (CLAUDE.md rule #8).
pub trait Check: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self) -> Result<CheckOutput>;
}

pub fn all_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(processes::ProcessCheck),
        Box::new(network::NetworkCheck),
        Box::new(persistence::PersistenceCheck),
        Box::new(accounts::AccountsCheck),
    ]
}
