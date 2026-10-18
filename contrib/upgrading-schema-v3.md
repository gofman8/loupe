# Upgrading the database to schema 6

Current schema-4 installations upgrade to schema 6 when the new server opens
the database. Schema 5 adds stable finding identities for report completion;
schema 6 records conservative source labels for stored content. Existing
findings, jobs, history, and content remain stored. Older schemas also apply
their pending migrations in the same transaction.

This upgrade retains the scan/verification runtime; it does not activate
survey or drilldown orchestration. Deploy the server and worker images from
the same release so the worker hardening is included. Keep all workers stopped
until the server has completed migration and opened its listener.

## Offline upgrade

1. Retain the old images/binaries and the database's matching master key.
   Rehearse the candidate upgrade and restoration on a copy of the production
   database. Check free space for schema work, indexes, and the journal/WAL;
   whole-table admission and integrity checks can take time on a large database.
2. Arrange a maintenance window. Allow in-flight work to finish where possible,
   then stop every worker, including automatic restarts. While the old server
   is still running, inspect outstanding jobs with the dashboard/API or
   `loupectl job list` and `loupectl job get ID`. Stopping workers does not
   clear leases. Wait for reaping or explicitly cancel abandoned jobs with
   `loupectl job cancel ID`; cancellation can discard unaccepted findings.
   Queued work may remain. Schema-2 upgrades refuse outstanding leases. From
   schema 1, the capability migration completes leased verify jobs with recorded
   verdicts and requeues other leases. The jobs rebuild also refuses conflicting
   active verification jobs.
3. Stop the old server and every other database user. Keep workers stopped
   through upgrade verification. WAL permits concurrent readers; it does not
   establish exclusive ownership for this maintenance procedure.
4. Take and verify a recoverable, consistent SQLCipher backup with your backup
   tooling. Follow its WAL/checkpoint requirements: copying only the main
   database file can omit committed data. Retain this final maintenance-window
   snapshot and the matching key. Loupe does not create or validate backups.
5. Start the new server with the existing database and key. For containers,
   follow [the deployment guide](docker/README.md). Adjust
   `LOUPE_SERVER_START_TIMEOUT_SECONDS` if the default 300-second wait is too
   short. Keep INFO logging enabled so the deployment helper can observe
   `loupe-server listening` for the new service invocation. A running systemd
   unit or `database ready` message alone does not establish listener readiness.
6. Once the listener is ready, check authenticated `/v1/health`, existing
   findings and search, and the reported schema version. Start the new workers
   and verify a queued scan and verification job complete normally. Do not
   enqueue phase kinds that have no production runtime handler.

## Migration refusal and recovery

All pending versions, stored-data admission, foreign-key and integrity checks,
both version markers, and foreign-key restoration belong to one transaction.
A detected migration error rolls that transaction back. A failed upgrade from
schema 4 remains schema 4; a failure from schema 1 remains schema 1. Journal
configuration can change outside the transaction; the guarantee concerns the
logical schema and rows, not byte-identical database files.

Admission checks include stored field policies and numeric ranges, runnable
verification targets, scheduling ownership, and agreement between the finding
search index and its content. Disabled/retired/terminal rows are also read.
Accepted legacy formats, registered future job kinds, and the existing malformed
scanner-JSON fallback remain supported. Validation does not rewrite historical
text, cancel jobs, or silently repair an inconsistent search index.

The server logs a migration failure's source/target versions, stage, table,
column, numeric row ID where available, and a closed reason or SQLite code.
Stored payloads and credentials are omitted. Stop the new server's restart loop,
retain the backup, and inspect the identified row or index with authorized
tooling. Correct the cause deliberately, then repeat the offline upgrade.
For a refused migration, the previous compatible binary can reopen the original
logical database. Do not edit version markers to bypass a refusal.

Older-schema lease or duplicate-verification refusals can be resolved with the
old server while workers remain stopped. Inspect and cancel only redundant or
abandoned jobs, then stop the server again before retrying. Report-identity
entropy/backfill failures also roll back all earlier pending migrations.

These checks are not a guarantee of detecting every conceivable bad database.
Full admission runs during upgrades; current-schema startup separately checks
unknown job kinds. Credential usability and remote services are checked by
their consumers. Backups remain necessary for storage faults and power loss.

## Rollback after migration succeeds

After commit the database is schema 6, which old schema-4 binaries reject.
TLS configuration, listener binding, or another later startup step can still
fail after that commit. A deployment timeout also does not undo the upgrade
and may leave the server still running; inspect its state before recovery.

There is no automatic downgrade. Stop all writers, restore the verified backup
with its matching key, and start the old images against that restored snapshot.
Restoration loses writes accepted after the backup. Before resuming workers,
prefer correcting a later startup problem and retrying the new server when the
migration itself succeeded. Once new work has been accepted, consider a forward
fix to avoid discarding it.

## Verification coverage

Encrypted historical fixtures cover preserved content and relationships,
queued claims, search results, and successful upgrades. Refusal tests compare
the original schema, rows, and markers after rollback and verify a deliberate
repair permits retry. Failure injection covers migration stages and later
backfill failures; a held reader exercises a real SQLite commit failure.

```sh
export CARGO_TARGET_DIR="$(mktemp -d /tmp/cargo-target-loupe-migrations.XXXXXX)"
cargo test -p loupe-storage migrations
cargo test -p loupe-server --test migration_startup
bash contrib/docker/test-server-readiness.sh
```

These tests complement, rather than replace, the production-data upgrade and
backup-restore rehearsal in the offline procedure.
