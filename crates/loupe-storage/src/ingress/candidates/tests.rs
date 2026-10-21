use super::*;

thread_local! {
	static OWNED_IDENTITY_DECODES: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
}

pub(super) fn observe_identity_decode(size: usize) {
	OWNED_IDENTITY_DECODES.with_borrow_mut(|sizes| sizes.push(size));
}

fn candidate() -> String {
	format!(
		r#"{{"kind":"lead","id":1,"producer_job_id":101,"commit_sha":"{}","created_at":9,"identity_family":"auth-bypass","identity_anchor":"entry e\u0301","identity_instance_key":null}}"#,
		"a".repeat(40)
	)
}
fn read(raw: &str) -> rusqlite::Result<Vec<Candidate<Agent, Db>>> {
	let conn = rusqlite::Connection::open_in_memory()?;
	conn.query_row("SELECT ?1", [raw], |row| snapshot(row, 0))
}

#[test]
fn snapshots_keep_fixed_sources_and_original_nested_identity_spans() {
	let original = candidate();
	let values = read(&format!("[{original}]")).unwrap();
	let _: &loupe_core::review_metadata::ReviewCommit<Db> = &values[0].commit_sha;
	let _: &Anchor<AnchorText, Agent> = &values[0].identity_anchor;
	assert_eq!(values[0].identity_anchor.expose(), "entry é");
	assert_eq!(values[0].commit_sha.expose(), "a".repeat(40));
	assert!(!format!("{:?}", values[0]).contains("entry"));
	struct Span;
	impl ValidateCarrying<&[u8], Db> for Span {
		type Output = ();
		type Error = Error;
		fn validate(self, u: Unvalidated<'_, &[u8], Db>) -> Result<(), Error> {
			#[derive(Deserialize)]
			struct Raw<'a> {
				#[serde(borrow)]
				identity_anchor: &'a RawValue,
			}
			let raw: Raw<'_> = serde_json::from_slice(u.get()).map_err(|_| invalid())?;
			let copied = RawValue::from_string(raw.identity_anchor.get().to_owned())
				.map_err(|_| invalid())?;
			assert_eq!(
				identity::<Anchor<AnchorText, Agent>>(&u, raw.identity_anchor)?.expose(),
				"entry é"
			);
			assert!(
				identity::<Anchor<AnchorText, Agent>>(&u, &copied).is_err(),
				"copied token cannot acquire the source of a different SQL allocation"
			);
			Ok(())
		}
	}
	let conn = rusqlite::Connection::open_in_memory().unwrap();
	conn.query_row("SELECT ?1", [original], |row| {
		column(row, 0)?.validate_carrying(Span).map_err(|error| admission_error(0, error))
	})
	.unwrap();
}

#[test]
fn snapshot_schema_and_collection_and_byte_bounds_are_closed() {
	let item = candidate();
	assert_eq!(read(&format!("[{}]", vec![item.as_str(); 20].join(","))).unwrap().len(), 20);
	assert!(read(&format!("[{}]", vec![item.as_str(); 21].join(","))).is_err());
	for invalid in [
		item.replace("\"id\":1", "\"id\":0"),
		item.replace("\"producer_job_id\":101", "\"producer_job_id\":0"),
		item.replace("\"kind\":\"lead\"", "\"kind\":\"other\""),
		item.replace("\"id\":1", "\"id\":1,\"id\":1"),
		item.replace('}', ",\"extra\":1}"),
		item.replace(&"a".repeat(40), "bad"),
		item.replace("auth-bypass", &"x".repeat(65)),
		item.replace("entry e\\u0301", &"x".repeat(601)),
	] {
		assert!(read(&format!("[{invalid}]")).is_err());
	}
	assert!(read(&format!("{}[]", " ".repeat(MAX_BYTES - 2))).is_ok());
	assert!(read(&format!("{}[]", " ".repeat(MAX_BYTES - 1))).is_err());
}

#[test]
fn family_bounds_precede_owned_decode_without_tightening_folded_anchors() {
	let at_limit = candidate().replace("auth-bypass", &"\\u0061".repeat(64));
	OWNED_IDENTITY_DECODES.with_borrow_mut(Vec::clear);
	assert_eq!(read(&format!("[{at_limit}]")).unwrap()[0].identity_family.expose(), "a".repeat(64));
	assert!(OWNED_IDENTITY_DECODES.with_borrow(|sizes| sizes.contains(&64)));

	let too_long = candidate().replace("auth-bypass", &"\\u0061".repeat(65));
	OWNED_IDENTITY_DECODES.with_borrow_mut(Vec::clear);
	assert!(read(&format!("[{too_long}]")).is_err());
	assert!(
		OWNED_IDENTITY_DECODES.with_borrow(Vec::is_empty),
		"overlong Family must reject before any owned identity decode"
	);

	// Anchors fold whitespace, so their decoded raw length must not be capped
	// at the normalized policy limit (nor at an arbitrary fixed multiple).
	let folded =
		candidate().replace("entry e\\u0301", &format!("entry{}boundary", "\\u0020".repeat(4000)));
	assert_eq!(read(&format!("[{folded}]")).unwrap()[0].identity_anchor.expose(), "entry boundary");
}
