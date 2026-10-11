//! Pure ownership decisions over facts loaded in the caller's transaction.
use crate::Ownership;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Assignment {
	Job(i64),
	Finding(i64),
	Verification(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubjectKind {
	Record,
	/// A generation-less, host-authored job can use its campaign's repository.
	Job {
		campaign_repo: Option<i64>,
	},
	Assigned(Assignment),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Subject {
	pub repo: i64,
	pub generation: Option<i64>,
	pub campaign: Option<i64>,
	pub kind: SubjectKind,
}

impl Subject {
	pub fn repository(repo: i64) -> Self {
		Self { repo, generation: None, campaign: None, kind: SubjectKind::Record }
	}
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Scope {
	pub repo: i64,
	pub generation: Option<i64>,
	pub campaign: Option<i64>,
	pub assignment: Option<Assignment>,
}

impl Scope {
	pub fn repository(repo: i64) -> Self {
		Self { repo, generation: None, campaign: None, assignment: None }
	}

	// Ownership is a diagnostic label, not a policy selector: e.g. JobLead is
	// used by both repository- and generation-bound callers. The loaded scope
	// and subject kind carry the actual constraints.
	pub fn admits(&self, subject: &Subject, _relation: Ownership) -> bool {
		if subject.repo != self.repo {
			return false;
		}
		if let Some(generation) = self.generation {
			let campaign_fallback = subject.generation.is_none()
				&& matches!(subject.kind, SubjectKind::Job { campaign_repo: Some(repo) } if repo == self.repo);
			if subject.generation != Some(generation) && !campaign_fallback {
				return false;
			}
		}
		if self.campaign.is_some() && subject.campaign != self.campaign {
			return false;
		}
		if self
			.assignment
			.is_some_and(|assignment| subject.kind != SubjectKind::Assigned(assignment))
		{
			return false;
		}
		true
	}

	/// Missing and foreign rows deliberately have the same public error.
	pub fn check(&self, subject: Option<&Subject>, relation: Ownership) -> Result<(), Ownership> {
		if subject.is_some_and(|subject| self.admits(subject, relation)) {
			Ok(())
		} else {
			Err(relation)
		}
	}
}
