# Copyright (c) 2026 onyks
# SPDX-License-Identifier: MIT
#
# Runner image for the NSE headless engine.
#
# NSE builds network namespaces and reads kernel trace events, so it needs
# CAP_NET_ADMIN and CAP_NET_RAW. Run it with:
#
#   podman run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
#       -v "$PWD/suite.yaml:/suite.yaml:ro" nse --file /suite.yaml
#
# The image exists so a firewall test suite can run on a pinned nftables
# version. That matters: the trace parser has broken across nftables releases
# before, so "which nft" is part of the test environment, not an accident of the
# host.
# Pinned by digest, not by tag: a tag is mutable, so `python:3.12-slim` is a
# different image tomorrow and the nftables version this image exists to pin
# would drift with it. Bump deliberately.
FROM docker.io/library/python:3.12-slim@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79

RUN apt-get update && apt-get install -y --no-install-recommends \
        nftables \
        iproute2 \
        conntrack \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY nse/ /app/nse/

RUN pip install --no-cache-dir ".[cli]"

ENTRYPOINT ["nse-runner"]
CMD ["--help"]
