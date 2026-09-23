# Test image: rust toolchain + go (bbolt spike) + reference sing-box-lx.
# Used by tests/docker/run.sh; sources are bind-mounted at /src.
FROM rust:1-bookworm

COPY --from=golang:1.25-bookworm /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:/usr/local/cargo/bin:$PATH

ARG SB_REF_VERSION=v1.14.1-lx.8
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends musl-tools; \
    rm -rf /var/lib/apt/lists/*; \
    rustup component add rustfmt clippy; \
    rustup target add x86_64-unknown-linux-musl; \
    curl -fsSL -o /tmp/ref.tar.gz \
      "https://github.com/Leadaxe/sing-box-lx/releases/download/${SB_REF_VERSION}/sing-box-${SB_REF_VERSION#v}-linux-amd64.tar.gz"; \
    mkdir -p /opt/ref; \
    tar -xzf /tmp/ref.tar.gz -C /opt/ref; \
    rm /tmp/ref.tar.gz; \
    REF="$(find /opt/ref -type f -name sing-box | head -1)"; \
    chmod +x "$REF"; \
    ln -sf "$REF" /usr/local/bin/sing-box-ref; \
    sing-box-ref version

ENV SING_BOX_REF=/usr/local/bin/sing-box-ref
WORKDIR /src
CMD ["bash", "tests/docker/inside.sh"]
