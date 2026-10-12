//! Opaque scanner configuration forwarded through its named domain endpoints.
//!
//! This document preserves unknown JSON with last-key-wins behavior, while
//! admitting selected scanner strings before forwarding them.
//! It is not semantic Payload and supplies no general Value extraction. Worker
//! operational settings are a separate, explicitly validated projection.

use std::marker::PhantomData;

use loupe_provenance::{Config, Db, Mark, Operator, Server, Source};
use serde::{Serialize, Serializer};
use serde_json::Value;

use crate::text::{checked, policy, Error, TextPolicy};

pub struct ScannerDocument<S: Source> {
	value: Value,
	source: PhantomData<S>,
}

// Only the four actual decoder owners can construct this forwarding document.
// Each call moves the already decoded field under its enclosing validation
// mark; the enclosing decoder retains the original JSON recursion budget.
macro_rules! decoded {
	($source:ty, $method:ident) => {
		impl ScannerDocument<$source> {
			pub fn $method(_: &Mark<'_, $source>, value: Value) -> Result<Self, Error> {
				validate_list::<policy::ScannerExtension>(&value, "include_extensions", 3)?;
				validate_list::<policy::ScannerExcludePattern>(
					&value,
					"exclude_path_substrings",
					4,
				)?;
				Ok(Self { value, source: PhantomData })
			}
		}
	};
}
decoded!(Config, configured);
decoded!(Operator, registered);
decoded!(Db, stored);
decoded!(Server, leased);

fn validate_list<P: TextPolicy>(value: &Value, name: &str, index: usize) -> Result<(), Error> {
	let selected = if value.is_array() { value.get(index) } else { value.get(name) };
	if let Some(Value::Array(values)) = selected {
		// Schema fallback does not exempt strings beside malformed list items.
		for value in values.iter().filter_map(Value::as_str) {
			checked::text::<P>(value)?;
		}
	}
	Ok(())
}

impl<S: Source> ScannerDocument<S> {
	/// The registration wire format omits only a null document.
	pub fn is_null(&self) -> bool {
		self.value.is_null()
	}
}
impl<S: Source> Clone for ScannerDocument<S> {
	fn clone(&self) -> Self {
		Self { value: self.value.clone(), source: PhantomData }
	}
}
impl<S: Source> PartialEq for ScannerDocument<S> {
	fn eq(&self, other: &Self) -> bool {
		self.value == other.value
	}
}
impl<S: Source> Eq for ScannerDocument<S> {}
impl<S: Source> std::fmt::Debug for ScannerDocument<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "ScannerDocument<{}>([redacted])", S::NAME)
	}
}
impl<S: Source> Serialize for ScannerDocument<S> {
	fn serialize<T: Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
		self.value.serialize(serializer)
	}
}
