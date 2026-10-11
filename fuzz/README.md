# Fuzzing

The rule the harness enforces:

> Every function that consumes bytes which originated outside the
> process has a fuzz target, and the target is written in the same
> change as the function.

"Outside the process" for Loupe means: a worker's request to the server
(and the agent text inside it), an operator's request, a server's
response to a worker, everything that crosses the sandbox boundary (the
MCP socket, the model-proxy socket, the CLI's output, the export
directory), the repository under review (file contents, paths, `git`
output), model-provider and report-destination responses, rows read
back from the database, and configuration. Being authenticated does not
make a source trusted: a worker that logged in is still a host that can
be compromised, and the agent text it relays is hostile by definition.

Layout:

- `fuzz/` (this crate, `loupe-fuzz`): one module per target in `src/`,
  each exposing `do_test(&[u8])`, `<name>_test(&[u8], Output)` and an
  `extern "C" <name>_run` for external fuzzers.
- `fuzz/runners/` (`loupe-fuzz-runners`): one generated binary per
  target in `src/bin/`, selecting the engine by feature:
  `afl_fuzz`, `honggfuzz_fuzz`, `libfuzzer_fuzz`, `stdin_fuzz`.
- `fuzz/src/bin/gen_target.sh` and `target_template.txt`: generate the
  runner binaries. CI fails if the generated files are stale.
- `fuzz/test_cases/<target>/`: committed inputs. Every runner binary has
  a `#[test]` that replays them, so `cargo test` in `runners/` is the
  regression suite for every crash ever found.
- `fuzz/src/utils/`: `test_logger` (output sinks), `input` (a bounded
  byte cursor for stateful targets), `arb` (structure-aware input over
  Loupe's own types) and `redact` (comparison with a fixed redacted
  rendering for the same public metadata).
- `fuzz/targets.h`: C prototypes of the `_run` entry points, for
  fuzzers driving the static library directly.

## Running

All commands from `fuzz/`. The `fuzzing` cfg is required so product
crates can swap deterministic stand-ins for randomness and time when
they need to.

Set `CARGO_TARGET_DIR` to a task-specific directory under `/tmp` before
running Cargo directly. The `ci/` wrappers choose one when it is unset.
`sh test-harness.sh` checks the generated C header, removal of stale
runners, and refusal to replay a missing corpus. It uses a private copy
under `/tmp` and never moves the real seeds.

Replay committed cases (this is also what CI's `fuzz-replay` job runs):

```sh
RUSTFLAGS="--cfg=fuzzing" cargo test --lib
RUSTFLAGS="--cfg=fuzzing" cargo test --manifest-path runners/Cargo.toml --features stdin_fuzz --bins
```

libFuzzer (needs nightly; `-s none` skips the sanitizer rebuild of std,
which is enough for pure Rust targets):

```sh
cargo install --force cargo-fuzz
cd runners && RUSTFLAGS="--cfg=fuzzing" rustup run nightly cargo fuzz run -s none --features libfuzzer_fuzz smoke_target -- -max_total_time=150
```

In this repository, run campaigns through `ci/fuzz.sh <target>
[seconds]` instead: it takes the machine-wide fuzz lock, seeds from
`test_cases/`, and applies the RSS and wall-time caps. If the link step
fails under the release profile's LTO, `ci/fuzz.sh` already sets
`CARGO_PROFILE_RELEASE_LTO=false`. Run one campaign at a time.

Continuous fuzzing: `ci/fuzz-continuous.sh [branch]` cycles through
every target on the branch in a fixed rotation with an equal time slice
each (`LOUPE_FUZZ_SLICE`, 300 s), resuming where it stopped, with a
persistent corpus per target under `$LOUPE_LOCAL/fuzz-continuous/`. It
is pinned to one CPU core (`LOUPE_FUZZ_CPU`, default the last) at the
lowest priority and does not take the fuzz lock. New crash inputs are
listed in `FOUND.log`; each one is triaged and fixed with a regression
test and the input committed as a seed, in one commit, on the branch
where it was found. The campaign starts as soon as the first targets
exist and keeps running while the rest of the work goes on.

honggfuzz and AFL++ work through the same runner features
(`cargo hfuzz run`, `cargo afl fuzz`); see the engines' own
documentation. honggfuzz needs binutils development headers (`bfd.h`).

Reproduce a crash from bytes, no files needed:

```sh
printf '\x02\x05\x00\x01' | RUSTFLAGS="--cfg=fuzzing" \
  cargo run --manifest-path runners/Cargo.toml --features stdin_fuzz --bin smoke_target
```

Panics abort the process (`panic = "abort"`), so a non-zero exit is the
signal. To keep a crash as a regression test, write the bytes to
`test_cases/<name>/<anything>` and commit it.

## Adding a target

1. Copy `src/smoke.rs` to `src/<name>.rs`, replace `smoke` with
   `<name>` in the three function names, write `do_test`.
2. Add `pub mod <name>;` to `src/lib.rs`, and the product crate to
   `Cargo.toml` if it is new.
3. Add `GEN_TEST <name>` to `src/bin/gen_target.sh` (alphabetical) and
   run it.
4. Put at least one valid input and one malformed input under
   `test_cases/<name>/`.
5. Add the file to `ci/unsafe-allow.txt` (the C entry point is
   `unsafe`), and run `ci/fuzz.sh <name>_target 120` before committing;
   record the run in the commit message ("fuzzed clean: N runs, M
   edges").

Names are `<crate>_<thing>` (`core_text_bounded`, `worker_mcp_rpc`).

## What a target should assert

Beyond "no panic": round trip (decode, re-encode, decode again,
compare), bounded output (output size is a function of input size with
a known constant), redaction (`format!("{:?}")` of a decoded value
matches its documented redacted rendering: `utils::redact::assert_redacted`),
and for renderers "no escape" (agent text appears only inside its
delimited block or fence). For stateful targets, that every state
transition is reachable only through the documented API. A target that
only checks for crashes is the minimum, not the goal.

For a fixed metadata shape, `Redaction::baseline` stores the exact expected
rendering. This avoids accidental matches between a payload and fixed text
such as `[redacted]`, and detects an extra leaked copy of those same bytes.
Types with variable public metadata must construct a matching baseline or
check their documented output directly. Do not exclude payload substrings
merely because those substrings also occur in the fixed template.

Two input shapes: a byte cursor (`utils::input::ByteSource`) for
parsers, where the attacker controls bytes; and `arbitrary` over
Loupe's own types (`utils::arb`) for typed, stateful targets
(transition sequences, policy snapshots, tool calls), which the fuzzer
mutates far better when it sees the structure. Both read the same raw
bytes, so corpus files stay plain files.

## Dependencies

The fuzz workspace is not a product workspace: `ci/gates.sh
gate_no_tool_deps` refuses a product crate that depends on it. Its own
dependencies are `arbitrary` (structure-aware input; maintained by the
rust-fuzz organisation, the same as `cargo-fuzz` and `libfuzzer-sys`)
and `serde_json` (already a product dependency). Anything else needs a
sentence here saying why.

`unicode-general-category` and `unicode-normalization` let text targets
independently check character categories and NFC instead of calling the
validator being tested. They use the same Unicode data as the product.

The initial lockfile uses `arbitrary` 1.5.0 and `libfuzzer-sys` 0.4.13.
`arbitrary` is confined to this unpublished workspace: derive it for local
input models that select product operations, rather than adding fuzz-only
traits to production types. For parsers, pass the original bytes directly;
for a sequence of operations, consume `ByteSource` or `Unstructured` until
exhaustion, with an explicit operation/allocation bound.

The first verified toolchain was stable Rust 1.95.0, nightly 1.97.0
(`b954122bb`, 2026-05-20), and cargo-fuzz 0.13.2. This host installs Cargo
tools in `/tmp/cargo-home/bin`, which must be on `PATH`; it has no `bfd.h`,
so libFuzzer is the active engine. Corpus replay needs neither that engine
nor nightly. The smoke campaign completed 7,554,177 runs with 34 covered
edges, and malformed-corpus checks were verified to fail before repair.

The ingress backlog below was checked against main `db99745` before adding
targets. The source inventory includes response accounting, repository
metadata, source discovery and network command output; these are parsing
boundaries even when their producer is authenticated or runs locally.

## Surfaces that need targets

Implemented targets (each corpus includes valid and malformed inputs):

| Target | Assertions |
|---|---|
| `core_text_bounded` | All ten policies: exact admission, raw/normalized caps, NFC, character categories, whitespace and metadata-only diagnostics |

Each becomes a target when the code is covered; the list is the
backlog, kept current by the stage briefs.

| Surface | Source | Target shape |
|---|---|---|
| Wire DTOs, both directions | worker, operator, server | single-shot, round trip |
| Agent text validators (`BoundedText`, `Identifier`, `RepoPath`, `BoundedJson`, `SourceRefs`) | agent | single-shot, oracle re-check |
| Canonical JSON and digests | worker | single-shot, idempotence |
| Job and finding state machines, verdict rollup | server | stateful (`arbitrary`) |
| Scheduler and admission policy snapshots | db, config | single-shot |
| MCP JSON-RPC dispatcher and tool arguments | sandbox | stateful over `ByteSource` |
| Model-broker request policy, header stripping, output ceiling | sandbox, provider | single-shot and stream |
| CLI stdout parsing (`extract_json_object`, verdicts) | sandbox | single-shot |
| Sandbox argv builder, network host validation, nft rules | config | single-shot, golden set |
| Worker and server configuration | config | single-shot |
| Report renderers (issue body and title, email message) | agent, db | single-shot, no-escape |
| Job-capability header parsing | worker | single-shot |
| Certificate fingerprinting, PEM loading | config | single-shot |
| Dashboard request handling, CLI rendering | browser, server | single-shot |
| Phase (v2) DTOs, typed evidence, inventory manifest, candidates, admission | worker, agent | single-shot, round trip (after the v2 endpoints land) |
| Prompt builder, report builder, canary scanner, citation check | agent, repo | single-shot, no-escape (Stage S3) |
| Provider JSON/SSE token accounting and response headers | provider | single-shot, independent usage/header oracle |
| Job filters, clone URLs, protocol headers, FTS query escaping | operator, worker | single-shot, parser-specific shape |
| Repository cursor and origin parsing | repo | single-shot, exact framing and round trip |
| Workspace manifests and source discovery | repo | bounded filesystem fixture and independent inventory |
| Regex scanner file content | repo | bounded filesystem fixture and match offsets |
| Network supervisor command output and nft input | sandbox, config | single-shot, syntax and golden output |
