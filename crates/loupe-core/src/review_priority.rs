//! Bounded proposal vocabulary; these values grant no scheduling authority.
use serde::{Deserialize, Serialize};

// debug-ok: proposal risk vocabulary contains only closed variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
	Low,
	Medium,
	High,
	Critical,
}

// debug-ok: proposal risk vocabulary contains only closed variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
	Privileged,
	Local,
	Remote,
}

// debug-ok: proposal risk vocabulary contains only closed variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
	Plausible,
	Traced,
}
