# loupe-http

Shared, bounded HTTP response transport for the Loupe worker, CLI, and web
clients. `read_response_bytes` collects at most `MAX_RESPONSE_BYTES =
16 * 1024 * 1024` bytes, including whitespace. It refuses a declared
oversized length before polling the body and checks each streamed chunk
before extending the buffer. Buffer capacity is capped too. It returns
`ResponseBodyError::TooLarge` without retaining or echoing the partial body.

The crate owns only transport: status handling, protocol checks, text
presentation, and JSON decoding remain in the clients. Keeping it separate
allows all three clients to share one limit without adding HTTP dependencies
to the pure protocol DTO crate or creating client-to-client dependencies.

The 16 MiB limit is an explicit transport budget, not a promise that every
valid list fits. Unbounded admin lists and large worker search summaries can
exceed it. Such responses fail explicitly without truncation; pagination is
future work. See `ARCH.md` for the fixture calculation and scope.

Run `cargo test -p loupe-http` from the workspace root, with
`CARGO_TARGET_DIR` set to a task-specific directory under `/tmp`.
