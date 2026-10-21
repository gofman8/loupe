//! Explicit operator reset is the only early-purge boundary. Canonical evidence
//! and receipts survive; a later ordinary open must choose a fresh bootstrap.
use super::*;

pub(super) fn admin(state: &AppState, offline: &common::offline::OfflineDatabase) -> PeerCert {
	let bundle = state.ca.mint_client("reset-admin").unwrap();
	let peer = PeerCert(
		CertificateDer::pem_slice_iter(bundle.cert_pem.as_bytes()).next().unwrap().unwrap(),
	);
	let id = registry::register_worker(
		&state.db,
		&common::marked::operator_ingress(),
		&common::marked::operator::text("reset-admin"),
		&loupe_tls::cert_fingerprint(peer.0.as_ref()),
		now(),
	)
	.unwrap();
	offline
		.external_corruption(|conn| {
			conn.execute("UPDATE workers SET kind='admin' WHERE id=?1", [id])?;
			Ok(())
		})
		.unwrap();
	peer
}

pub(super) async fn reset(
	state: &AppState, generation: i64, peer: &PeerCert,
) -> (StatusCode, Value) {
	let mut req = Request::post(format!("/v1/review-generations/{generation}/reset"))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header("content-type", "application/json")
		.body(Body::from(r#"{"protocol_version":3}"#))
		.unwrap();
	req.extensions_mut().insert(peer.clone());
	let response = router(state.clone()).call(req).await.unwrap();
	let status = response.status();
	assert_ne!(status, StatusCode::NOT_FOUND, "operator reset route must exist");
	assert_eq!(
		response.headers().get("cache-control").and_then(|v| v.to_str().ok()),
		Some("no-store")
	);
	let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
	(status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn quiescent_reset_purges_derived_state_and_next_open_bootstraps() {
	let f = fixture();
	let generation = prepare(&f).await;
	let peer = admin(&f.state, &f.offline);
	f.offline
		.external_corruption(|conn| {
			conn.execute("UPDATE jobs SET state='cancelled' WHERE id=?1", [f.job])?;
			conn.execute(
				"UPDATE review_campaigns SET state='cancelled' WHERE campaign_id=?1",
				[f.campaign],
			)?;
			Ok(())
		})
		.unwrap();
	let (status, reply) = reset(&f.state, generation, &peer).await;
	assert_eq!(status, StatusCode::OK, "quiescent reset endpoint: {reply}");
	assert_eq!(reply["inventory_entries_removed"], 3);
	assert_eq!(reply["verification_intents_blocked"], 0);
	f.offline
		.external_corruption(|conn| {
			assert_eq!(conn.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_, i64>(0))?, 1);
			Ok(())
		})
		.unwrap();
	let replacement = common::with_repo(&f.state.db, 1, |scope| {
		let retired = loupe_storage::generations::get(scope, generation)?.unwrap();
		assert_eq!(retired.state, loupe_storage::generations::State::Retired);
		assert!(
			retired.generated_profile.is_none()
				&& retired.inventory_digest.is_none()
				&& retired.pending_follow_up.is_none()
		);
		let campaign::Opened::Created { campaign_id, job_id } = campaign::open(
			scope,
			&campaign::OpenCampaign {
				trigger: loupe_storage::campaigns::Trigger::Manual,
				requested_ref: campaign::RequestedRef::Pinned(&common::marked::operator::text(SHA)),
				base_sha: None,
				kind_hint: campaign::KindHint::Incremental,
			},
			&ReviewPolicy::default(),
			now(),
		)?
		else {
			panic!("fresh campaign")
		};
		let campaign = loupe_storage::campaigns::get(scope, campaign_id)?.unwrap();
		assert_eq!(campaign.recipe, loupe_storage::campaigns::Recipe::Bootstrap);
		let fresh =
			loupe_storage::generations::get(scope, campaign.generation_id.unwrap())?.unwrap();
		assert_ne!(
			fresh.generation_id, generation,
			"A reset generation ID must never name its replacement"
		);
		assert_eq!(fresh.state, loupe_storage::generations::State::Building);
		assert_eq!(fresh.coverage, loupe_storage::generations::Coverage::Unknown);
		assert!(fresh.generated_profile.is_none());
		assert!(fresh.predecessor_generation_id.is_none());
		assert_eq!(
			loupe_storage::jobs::get(scope, job_id)?.unwrap().kind,
			loupe_core::JobKind::Survey
		);
		Ok(fresh.generation_id)
	})
	.unwrap();
	f.offline
		.external_corruption(|conn| {
			conn.execute(
				"UPDATE jobs SET state='cancelled' WHERE state IN('queued','leased')",
				[],
			)?;
			conn.execute("UPDATE review_campaigns SET state='cancelled' WHERE state='active'", [])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(
		reset(&f.state, generation, &peer).await.0,
		StatusCode::CONFLICT,
		"An old request cannot reset its quiescent replacement"
	);
	common::with_repo(&f.state.db, 1, |scope| {
		let fresh = loupe_storage::generations::get(scope, replacement)?.unwrap();
		assert_eq!(fresh.state, loupe_storage::generations::State::Building);
		Ok(())
	})
	.unwrap();
}

#[tokio::test]
async fn reset_refuses_busy_generation_and_worker_authority_without_mutation() {
	let f = fixture();
	let generation = prepare(&f).await;
	let peer = admin(&f.state, &f.offline);
	assert_eq!(reset(&f.state, generation, &f.peer).await.0, StatusCode::FORBIDDEN);
	for queued in [false, true] {
		f.offline
			.external_corruption(|conn| {
				conn.execute(
					"UPDATE jobs SET state=?1 WHERE id=?2",
					params![if queued { "queued" } else { "leased" }, f.job],
				)?;
				Ok(())
			})
			.unwrap();
		assert_eq!(reset(&f.state, generation, &peer).await.0, StatusCode::CONFLICT);
	}
	f.offline
		.external_corruption(|conn| {
			conn.execute("UPDATE jobs SET state='cancelled' WHERE id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(
		reset(&f.state, generation, &peer).await.0,
		StatusCode::CONFLICT,
		"active campaign remains busy"
	);
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row("SELECT COUNT(*) FROM generation_inventory", [], |r| r
					.get::<_, i64>(0))?,
				3
			);
			assert_eq!(
				conn.query_row("SELECT state FROM review_generations", [], |r| r
					.get::<_, String>(0))?,
				"building"
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn reset_requires_strict_bounded_protocol_and_active_admin() {
	let f = fixture();
	let generation = prepare(&f).await;
	let peer = admin(&f.state, &f.offline);
	for (raw, version, authenticated, expected) in [
		(r#"{"protocol_version":3,"extra":true}"#.to_string(), "3", true, 400),
		(r#"{"protocol_version":3,"protocol_version":3}"#.to_string(), "3", true, 400),
		(r#"{"protocol_version":2}"#.to_string(), "3", true, 400),
		(r#"{"protocol_version":3}"#.to_string(), "2", true, 400),
		(" ".repeat(8193), "3", true, 413),
		(r#"{"protocol_version":3}"#.to_string(), "3", false, 401),
	] {
		let mut req = Request::post(format!("/v1/review-generations/{generation}/reset"))
			.header(PROTOCOL_VERSION_HEADER, version)
			.header("content-type", "application/json")
			.body(Body::from(raw))
			.unwrap();
		if authenticated {
			req.extensions_mut().insert(peer.clone());
		}
		let reply = router(f.state.clone()).call(req).await.unwrap();
		assert_eq!(reply.status().as_u16(), expected);
		assert_eq!(reply.headers()["cache-control"], "no-store");
		let bytes = to_bytes(reply.into_body(), 4096).await.unwrap();
		assert!(serde_json::from_slice::<Value>(&bytes).unwrap()["error"]["code"].is_string());
	}
	f.offline
		.external_corruption(|conn| {
			conn.execute("UPDATE workers SET revoked_at=?1 WHERE name='reset-admin'", [now()])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(reset(&f.state, generation, &peer).await.0, StatusCode::UNAUTHORIZED);
}
