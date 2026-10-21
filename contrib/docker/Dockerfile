ARG RUST_VERSION=1.99.1

FROM rust:${RUST_VERSION}-trixie AS app-builder
WORKDIR /src
ARG DEPENDENCY_REFRESH
RUN apt-get update \
	&& apt-get upgrade -y \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		cmake \
		libssl-dev \
		make \
		perl \
		pkg-config \
		zlib1g-dev \
	&& rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p loupe-server -p loupe-worker -p loupe-cli

FROM rust:${RUST_VERSION}-trixie AS bkb-mcp-builder
ARG DEPENDENCY_REFRESH
RUN apt-get update \
	&& apt-get upgrade -y \
	&& rm -rf /var/lib/apt/lists/*
ARG BKB_MCP_VERSION=0.3.0
# Resolve current compatible dependencies when building, just as the agent CLIs
# below do, never at runtime.
RUN cargo install bkb-mcp --version "=${BKB_MCP_VERSION}"

FROM rust:${RUST_VERSION}-trixie AS worker-rust
# Export real binaries and their sysroot, without per-user rustup state.
RUN rustup component add rustfmt clippy \
	&& cp -a "$(rustc --print sysroot)" /worker-rust

FROM debian:trixie-slim AS loupe-server
ARG DEPENDENCY_REFRESH
# No `ca-certificates` here: loupe-server's only outbound TLS is the
# GitHub reporter, which uses reqwest + rustls with webpki-roots
# compiled into the binary (see workspace Cargo.toml). Sendmail is
# local. Worker / admin mTLS pins the private loupe CA explicitly.
RUN apt-get update \
	&& apt-get upgrade -y \
	&& apt-get install -y --no-install-recommends tini \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd --uid 10001 --user-group --home-dir /var/lib/loupe --create-home --shell /usr/sbin/nologin loupe
# The revision changes on every commit; keep it below the package layers so
# they stay cached, and above the binaries it describes.
ARG LOUPE_BUILD_REVISION=unknown
ENV LOUPE_BUILD_REVISION=$LOUPE_BUILD_REVISION
LABEL org.opencontainers.image.revision=$LOUPE_BUILD_REVISION
COPY --from=app-builder /src/target/release/loupe-server /usr/local/bin/loupe-server
COPY --from=app-builder /src/target/release/loupectl /usr/local/bin/loupectl
COPY contrib/docker/loupe-container-entrypoint.sh /usr/local/bin/loupe-container-entrypoint
RUN chmod 0755 /usr/local/bin/loupe-container-entrypoint \
	&& install -d -o loupe -g loupe -m 0700 /var/lib/loupe /run/loupe
USER loupe
WORKDIR /var/lib/loupe
ENV LOUPE_BIND=0.0.0.0:8443 \
	LOUPE_DB=/var/lib/loupe/loupe.sqlite
EXPOSE 8443
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/loupe-container-entrypoint"]
CMD ["loupe-server", "serve"]

FROM node:24-trixie-slim AS loupe-worker
ENV NPM_CONFIG_AUDIT=false \
	NPM_CONFIG_FUND=false \
	NPM_CONFIG_UPDATE_NOTIFIER=false
ARG DEPENDENCY_REFRESH
RUN apt-get update \
	&& apt-get upgrade -y \
	&& apt-get install -y --no-install-recommends \
		bubblewrap ca-certificates git iproute2 nftables slirp4netns tini util-linux \
		autoconf automake bison build-essential cmake curl flex libtool ninja-build patch pkgconf \
		golang-go default-jdk-headless python3 python3-dev python3-venv \
		capnproto libboost-dev libcapnp-dev libevent-dev libsqlite3-dev libssl-dev \
		libzmq3-dev systemtap-sdt-dev zlib1g-dev \
		libgl-dev libqrencode-dev qt6-base-dev qt6-l10n-tools qt6-tools-dev \
		qt6-tools-dev-tools qt6-wayland \
		unzip xz-utils zip \
	&& nsenter --help | grep -q -- --user-parent \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd --uid 10002 --user-group --home-dir /var/lib/loupe-worker --create-home --shell /usr/sbin/nologin loupe-worker
# The sandbox hides /etc/alternatives and Java's /etc configuration. Resolve
# compiler aliases (including cc/c++) and JDK data into the read-only /usr tree.
RUN find /usr/bin -maxdepth 1 -type l -lname '/etc/alternatives/*' \
		-exec sh -ec 'for link do ln -sf "$(readlink -f "$link")" "$link"; done' sh {} + \
	&& find "$(readlink -f /usr/lib/jvm/default-java)" -type l -lname '/etc/*' \
		-exec sh -ec 'for link do cp --remove-destination "$(readlink -f "$link")" "$link"; done' sh {} +
COPY --from=worker-rust /worker-rust/ /usr/local/
# Resolve current releases when building an image, never inside a running
# worker. Explicit versions remain available for rollback or diagnosis.
ARG CLAUDE_CODE_VERSION=latest
ARG CODEX_VERSION=latest
ARG INSTALL_CLAUDE=1
ARG INSTALL_CODEX=1
# DEPENDENCY_REFRESH also invalidates this layer on every helper invocation.
RUN if [ "$INSTALL_CLAUDE" = "1" ]; then npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"; fi \
	&& if [ "$INSTALL_CODEX" = "1" ]; then npm install -g "@openai/codex@${CODEX_VERSION}"; fi
# See the server stage: revision metadata sits below every package layer.
ARG LOUPE_BUILD_REVISION=unknown
ENV LOUPE_BUILD_REVISION=$LOUPE_BUILD_REVISION
LABEL org.opencontainers.image.revision=$LOUPE_BUILD_REVISION
COPY --from=app-builder /src/target/release/loupe-worker /usr/local/bin/loupe-worker
COPY --from=bkb-mcp-builder /usr/local/cargo/bin/bkb-mcp /usr/local/bin/bkb-mcp
COPY contrib/docker/loupe-container-entrypoint.sh /usr/local/bin/loupe-container-entrypoint
RUN chmod 0755 /usr/local/bin/loupe-container-entrypoint \
	&& install -d -o loupe-worker -g loupe-worker -m 0700 /var/lib/loupe-worker /var/cache/loupe-worker /run/loupe
USER loupe-worker
WORKDIR /var/lib/loupe-worker
ENV HOME=/var/lib/loupe-worker
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/loupe-container-entrypoint"]
CMD ["loupe-worker", "run"]
