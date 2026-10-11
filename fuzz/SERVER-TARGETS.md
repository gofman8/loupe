# Server ingress targets

These targets exercise the pure functions used by production HTTP handlers and
reporters. `server_config` additionally writes each input into a temporary file
and calls the actual `FileConfig::load`; its paths are resolved against that
file's absolute parent directory. Targets never add files to the source corpus
while a campaign runs.

| Target | Input and oracle |
| --- | --- |
| `server_capability_header` | Raw header bytes; exact 43-byte admission for printable ASCII **or HTAB**, the current `HeaderValue::to_str` predicate. No base64url alphabet restriction. Accepted bytes hash unchanged; rejection has one fixed diagnostic. |
| `server_report_github` | JSON `Finding`; title normalization and 100-character cap, body admission at 65,536 Unicode scalar values. A separate fence scanner observes the deferred containment property. |
| `server_report_email` | JSON object with `from`, `to`, `subject`, and `finding`; CR/LF validation equivalence and exact header block independent of finding content. |
| `server_config` | Raw TOML bytes; strict UTF-8, parsed paths are absolute and resolved against the config directory, unknown root keys and empty GitHub owner lists are rejected. Other review values retain the loader's current permissive behavior. |
| `server_request_parsers` | Selector byte modulo five, then bytes: protocol header, state filter, kind filter, clone URL, FTS search. Bit 7 selects an absent optional field for the first three cases. |
| `server_github_response` | Selector byte modulo five, little-endian u16 HTTP status, then body bytes: app metadata, installation lookup, token, issue receipt, label result. Missing status defaults to 200. Errors must match the complete metadata-only diagnostic; decoded credentials have constant redacted Debug output. |

The protocol oracle recognizes unsigned decimal with an optional leading plus,
including leading zeros. `JobKind::from_str` is infallible: unknown strings become
`Unknown`, which the route refuses. Clone URL parsing remains permissive: HTTPS
hostnames can be empty, empty path components are skipped, and extra components
are ignored. FTS filtering uses byte lengths and inserts its own double quotes;
the input's quotes and other operators are stripped.

GitHub's `escape-closing-fence` seed and email's `escape-oversize-body` seed are
acceptance inputs for S3. Main currently renders description/title content outside
fences and uses fixed PoC fences; email has no body cap. The email seed exceeds
65,536 bytes as a concrete large-body example; S3 still needs to choose its email
destination cap. These properties are observed rather than asserted as existing
guarantees. The fence scanner has positive and negative examples to ensure that
it distinguishes enclosed content from plain text and embedded closing fences.

L8 keeps remote bodies and serde details out of reporter error chains while
retaining status, operation and configured request identifiers. Real HTTP
regressions cover all five operations and malformed success JSON, and failed
before the correction. The target independently models typed-serde object and
exact-sequence forms, duplicate/required-field checks, and ignored-value syntax.
Unknown fields can contain bytes that a whole-body JSON Value decoder rejects;
known credential and identifier fields still require their declared types.

Additional fuzz-only dependencies are the existing product crates and their
existing `http`, `blake3`, `serde`, `toml`, and `tempfile` libraries: header/hash
oracles, corpus shapes, independent TOML inspection, and filesystem loader
fixtures respectively. None is introduced into a product dependency graph.
