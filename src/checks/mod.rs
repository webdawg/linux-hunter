// SPDX-License-Identifier: AGPL-3.0-or-later
pub mod network;
pub mod persistence;
pub mod processes;

use crate::report::Finding;
use anyhow::Result;

/// A single category of compromise indicator. Each check inspects one
/// corner of the system and returns whatever it finds suspicious;
/// an empty result means the check ran and found nothing to flag.
pub trait Check: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self) -> Result<Vec<Finding>>;
}

pub fn all_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(processes::ProcessCheck),
        Box::new(network::NetworkCheck),
        Box::new(persistence::PersistenceCheck),
    ]
}
