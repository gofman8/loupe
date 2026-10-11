//! Bounded proofs of domain decisions. Run through `ci/kani.sh`.

use crate::{initial_job_state, JobState, JobTransition};

// invariant: I5. Bound: all nine transition variants; no input is omitted.
// This first proof also checks the verifier against the real core crate.
// ci: fast
#[kani::proof]
fn initial_job_state_requires_enqueue() {
	let choice: u8 = kani::any();
	kani::assume(choice < 9);
	let transition = match choice {
		0 => JobTransition::Enqueue,
		1 => JobTransition::Lease,
		2 => JobTransition::Heartbeat,
		3 => JobTransition::CompleteSucceeded,
		4 => JobTransition::CompleteFailed,
		5 => JobTransition::Cancel,
		6 => JobTransition::Retry,
		7 => JobTransition::ReapToQueued,
		_ => JobTransition::ReapToFailed,
	};
	let result = initial_job_state(transition);
	if choice == 0 {
		assert!(matches!(result, Ok(JobState::Queued)));
	} else {
		assert!(result.is_err());
	}
	kani::cover!(result.is_ok(), "initial enqueue is reachable");
	kani::cover!(result.is_err(), "noninitial transitions are rejected");
}
