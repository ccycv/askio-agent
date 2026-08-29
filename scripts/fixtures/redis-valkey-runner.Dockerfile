FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates socat \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT []
