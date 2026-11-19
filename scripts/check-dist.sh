#!/usr/bin/env bash
# Copyright (c) 2026 onyks
# SPDX-License-Identifier: MIT
#
# Install the built wheel and sdist in clean virtualenvs, outside the checkout,
# and use them the way a consumer does: the core alone, then the CLI extra.
# Each install must pass `pip check`, expose every 2.1.2 name with a compatible
# signature, import from the virtualenv rather than the checkout, and - with the
# CLI - load every example suite. Privileged behaviour is the integration
# suite's job; this is about what the packages contain.
#
#   scripts/check-dist.sh PYTHON DIST_DIR
set -euo pipefail

python=${1:?usage: check-dist.sh PYTHON DIST_DIR}
dist=$(cd "${2:?usage: check-dist.sh PYTHON DIST_DIR}" && pwd)
repo=$(cd "$(dirname "$0")/.." && pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/pyproject.toml")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

shopt -s nullglob
wheels=("$dist"/network_sandbox_engine-"$version"-*.whl)
sdists=("$dist"/network_sandbox_engine-"$version".tar.gz)
if [ "${#wheels[@]}" -ne 1 ] || [ "${#sdists[@]}" -ne 1 ]; then
    echo "!!! expected one wheel and one sdist for $version in $dist" >&2
    exit 1
fi

# Inputs the installed package is checked with, copied out of the checkout so
# nothing below can import from it.
cp "$repo/scripts/api_surface.py" "$repo/tests/data/api-2.1.2.json" "$work/"
cp -r "$repo/examples" "$work/examples"
cd "$work"

check_install() {
    local kind=$1 artifact=$2 venv="$work/venv-$1"
    echo "==> $kind: $(basename "$artifact") with $("$python" --version)"
    "$python" -m venv "$venv"
    local py="$venv/bin/python"
    "$py" -m pip install -q --upgrade pip
    "$py" -m pip install -q "$artifact"
    "$py" -m pip check
    "$py" -I - "$venv" "$version" <<'EOF'
import sys
from pathlib import Path

import nse

venv, version = Path(sys.argv[1]).resolve(), sys.argv[2]
location = Path(nse.__file__).resolve()
assert venv in location.parents, f"nse imported from {location}, not the virtualenv"
assert nse.__version__ == version, (nse.__version__, version)
try:
    import yaml  # noqa: F401
except ImportError:
    pass
else:
    raise AssertionError("the core install pulled in PyYAML; it belongs to the [cli] extra")
print(f"core: nse {nse.__version__} from {location.parent}")
EOF
    "$py" -I api_surface.py check api-2.1.2.json --installed --import
    test -x "$venv/bin/nse-runner"
    # Without the extra, the runner must say what is missing instead of a traceback.
    local status=0 output
    output=$("$venv/bin/nse-runner" --file examples/workstation.yaml 2>&1) || status=$?
    if [ "$status" -eq 0 ] || ! grep -qi "pyyaml\|\[cli\]" <<<"$output"; then
        echo "!!! nse-runner without the CLI extra: exit $status: $output" >&2
        exit 1
    fi

    "$py" -m pip install -q "${artifact}[cli]"
    "$py" -m pip check
    "$venv/bin/nse-runner" --help > /dev/null
    "$py" -I - examples <<'EOF'
import sys
from pathlib import Path

import yaml

from nse.cli.runner import build_case

suites = sorted(Path(sys.argv[1]).glob("*.yaml"))
assert suites, "no example suites"
cases = 0
for suite in suites:
    for index, raw in enumerate(yaml.safe_load(suite.read_text())["tests"]):
        _, request, expected = build_case(raw, index)
        assert len(expected) == len(request.packets), suite
        cases += 1
print(f"cli: {len(suites)} example suites, {cases} cases load")
EOF
}

check_install wheel "${wheels[0]}"
check_install sdist "${sdists[0]}"

# The wheel ships the engine and its license, and nothing from the checkout.
"$python" - "${wheels[0]}" <<'EOF'
import sys
import zipfile

names = zipfile.ZipFile(sys.argv[1]).namelist()
stray = [n for n in names if not n.startswith(("nse/", "network_sandbox_engine-"))]
assert not stray, f"unexpected files in the wheel: {stray}"
assert any(n.endswith("licenses/LICENSE") for n in names), "LICENSE missing from the wheel"
print(f"wheel: {len(names)} files, engine and metadata only")
EOF
echo "==> Distributions check passed with $("$python" --version)."
