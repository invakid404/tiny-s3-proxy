FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release --locked \
    && strip target/release/tiny-s3-proxy

FROM alpine:3 AS runtime

# Minimum trust-store release addressing the October 2026 eMudhra compromise.
RUN apk add --no-cache 'ca-certificates>=20261020-r0' tini

COPY --from=builder /build/target/release/tiny-s3-proxy /usr/local/bin/

RUN addgroup -S proxy && adduser -S proxy -G proxy
USER proxy

ENTRYPOINT ["tini", "--"]
CMD ["tiny-s3-proxy"]
