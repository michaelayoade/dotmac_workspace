#!/usr/bin/env bash
#
# From-wheel boot: the Workspace imports and STARTS from built wheels, resolved
# from the private index — not from this checkout, and not from a sibling one.
#
# B3/B4 asked for exactly this evidence, and the reason is narrow. `poetry
# install` puts `src/` on the path, so every other job in this repository proves
# the code works when the source tree is present. A deployment has no source
# tree; it has a wheel and whatever the index resolved. The failures that hide in
# that gap are real and boring: package data that was never declared (the
# Alembic lineages, `py.typed`), a `__file__`-relative path that only exists in a
# checkout, a dependency that was satisfied by the dev group.
#
# What a green run proves, beyond "it imports":
#
#   * the pinned `dotmac-kernel` and `dotmac-application-directory` are actually
#     PUBLISHED and resolvable, rather than merely written down;
#   * `create_app` composed the launcher and the directory module — including
#     validating that every permission code stamped on a mounted route is
#     declared by an installed manifest, so `workspace.applications.read` cannot
#     be enforced by a guard nothing declares;
#   * the process serves `/health` with no database reachable at all.
#
# Everything is a knob with a documented default. Credentials for the private
# index arrive through `PIP_EXTRA_INDEX_URL` (or `pip`'s own config) and are
# never echoed — no `set -x` here, on purpose.

set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
# Poetry's own default output directory. Named here rather than inlined so a
# caller can move it, and not passed to `poetry build` as a flag because the
# flag's availability varies across Poetry majors and this script must not.
BUILD_DIR="${BUILD_DIR:-dist}"
BOOT_VENV="${BOOT_VENV:-.boot-venv}"
BOOT_HOST="${BOOT_HOST:-127.0.0.1}"
BOOT_PORT="${BOOT_PORT:-8123}"
BOOT_ATTEMPTS="${BOOT_ATTEMPTS:-30}"
BOOT_INTERVAL="${BOOT_INTERVAL:-1}"
# Deliberately unreachable. `/health` is DB-free by design, so a boot that needs
# a database is a boot that has grown a startup dependency nobody intended.
BOOT_DATABASE_URL="${BOOT_DATABASE_URL:-postgresql+psycopg://unused:unused@127.0.0.1:1/unused}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

rm -rf "$BUILD_DIR" "$BOOT_VENV"

echo "==> Building the dotmac-workspace wheel"
poetry build --format wheel

echo "==> Creating a clean virtualenv (no repo venv, no src/ on the path)"
"$PYTHON_BIN" -m venv "$BOOT_VENV"
"$BOOT_VENV/bin/python" -m pip install --quiet --upgrade pip

echo "==> Installing the wheel and resolving its pins from the index"
# The wheel's own metadata carries the exact pins. If either is unpublished this
# is where the run fails — which is the point: an unpublished pin must be a
# loud, reported failure and never something worked around with a path
# dependency (AGENTS.md §6).
"$BOOT_VENV/bin/python" -m pip install --quiet "$BUILD_DIR"/dotmac_workspace-*.whl

echo "==> Proving the checkout is not what is being imported"
# Run from a directory that contains no `src/`, so a `dotmac_workspace` that
# resolved from this tree rather than from site-packages is caught here.
BOOT_TMP="$(mktemp -d)"
trap 'rm -rf "$BOOT_TMP"' EXIT
(
  cd "$BOOT_TMP"
  DATABASE_URL="$BOOT_DATABASE_URL" "$REPO_ROOT/$BOOT_VENV/bin/python" - <<'PY'
import pathlib
import sys

import dotmac_workspace

location = pathlib.Path(dotmac_workspace.__file__).resolve()
if "site-packages" not in location.parts:
    sys.exit(f"dotmac_workspace was imported from {location}, not from the wheel")
print(f"imported from {location}")
PY
)

echo "==> Booting the application from the wheel"
(
  cd "$BOOT_TMP"
  DATABASE_URL="$BOOT_DATABASE_URL" \
    "$REPO_ROOT/$BOOT_VENV/bin/python" -m uvicorn dotmac_workspace.main:app \
    --host "$BOOT_HOST" --port "$BOOT_PORT" &
  echo $! >"$BOOT_TMP/boot.pid"
)
BOOT_PID="$(cat "$BOOT_TMP/boot.pid")"
trap 'kill "$BOOT_PID" 2>/dev/null || true; rm -rf "$BOOT_TMP"' EXIT

for _ in $(seq 1 "$BOOT_ATTEMPTS"); do
  if curl -sf "http://$BOOT_HOST:$BOOT_PORT/health" >/dev/null; then
    echo "==> /health served from the installed wheel"
    exit 0
  fi
  sleep "$BOOT_INTERVAL"
done

echo "!! the application never served /health from the wheel" >&2
exit 1
