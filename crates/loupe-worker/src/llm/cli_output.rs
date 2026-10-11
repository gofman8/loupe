//! Bounded stdout/stderr capture shared by both CLI backends.
//!
//! Keep at most 1 MiB per stream, retaining the beginning and the end for
//! diagnostics. Continue draining discarded bytes so neither pipe can stall
//! the child. The caller's request deadline bounds draining and process wait.

use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const MAX_CLI_OUTPUT_BYTES: usize = 1024 * 1024;

pub(crate) struct CapturedOutput {
	pub bytes: Vec<u8>,
	pub truncated: bool,
}

pub(crate) async fn collect_cli_output(
	mut reader: impl AsyncRead + Unpin,
) -> std::io::Result<CapturedOutput> {
	let mut bytes = Vec::new();
	let mut chunk = [0; 8192];
	let mut truncated = false;
	let mut tail_cursor = 0;
	const TAIL_BYTES: usize = MAX_CLI_OUTPUT_BYTES / 2;
	loop {
		let count = reader.read(&mut chunk).await?;
		if count == 0 {
			break;
		}
		let kept = count.min(MAX_CLI_OUTPUT_BYTES - bytes.len());
		let required = bytes.len() + kept;
		if required > bytes.capacity() {
			bytes.reserve_exact(required.next_power_of_two() - bytes.len());
		}
		bytes.extend_from_slice(&chunk[..kept]);
		let mut discarded = &chunk[kept..count];
		truncated |= !discarded.is_empty();
		while !discarded.is_empty() {
			let len = discarded.len().min(TAIL_BYTES - tail_cursor);
			let start = TAIL_BYTES + tail_cursor;
			bytes[start..start + len].copy_from_slice(&discarded[..len]);
			discarded = &discarded[len..];
			tail_cursor = (tail_cursor + len) % TAIL_BYTES;
		}
	}
	if truncated {
		bytes[TAIL_BYTES..].rotate_left(tail_cursor);
	}
	Ok(CapturedOutput { bytes, truncated })
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn exact_budget_is_retained_and_not_marked_truncated() {
		let input = vec![b'x'; MAX_CLI_OUTPUT_BYTES];
		let captured = collect_cli_output(input.as_slice()).await.unwrap();
		assert_eq!(captured.bytes, input);
		assert!(!captured.truncated);
		assert!(captured.bytes.capacity() <= MAX_CLI_OUTPUT_BYTES);
	}

	#[tokio::test]
	async fn wrapping_tail_preserves_the_first_and_last_bytes() {
		let input: Vec<_> = (0..MAX_CLI_OUTPUT_BYTES * 3 + 37).map(|i| (i % 251) as u8).collect();
		let captured = collect_cli_output(input.as_slice()).await.unwrap();
		let half = MAX_CLI_OUTPUT_BYTES / 2;
		assert!(captured.truncated);
		assert_eq!(captured.bytes.len(), MAX_CLI_OUTPUT_BYTES);
		assert!(captured.bytes.capacity() <= MAX_CLI_OUTPUT_BYTES);
		assert_eq!(captured.bytes[..half], input[..half]);
		assert_eq!(captured.bytes[half..], input[input.len() - half..]);
	}
}
