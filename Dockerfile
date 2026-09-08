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
FROM python:3.12-slim

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
