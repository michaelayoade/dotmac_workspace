#!/usr/bin/env bash
# Print the image reference the deploy path is allowed to run — or refuse.
#
# `deploy/rendered/docker-compose.yml` is the AUTHORITY for which image the
# Workspace runs. It is rendered from `deploy/product.toml` by the pinned
# `dotmac-deployment-foundation` and byte-checked in CI, so the reference below
# cannot be edited without a reviewable diff.
#
# ## What this replaces
#
# The root compose file used to read
#
#     image: ${WORKSPACE_IMAGE:-registry.dotmac.io/dotmac/workspace}:${WORKSPACE_TAG:-latest}
#
# so a bare `docker compose up -d` on a host with no `.env` pulled whatever
# `:latest` pointed at that morning. A tag is a registry POINTER: it can be
# repushed after the thing it named was tested, which makes "the image we
# verified" and "the image the host runs" two different facts that look
# identical in every log. `WORKSPACE_TAG` is retired; the root compose declares
# `${WORKSPACE_IMAGE:?…}` with NO default, so an unpinned host refuses to start
# rather than floating.
#
# ## Why a digest and nothing else
#
# `name@sha256:<64 hex>` names exactly one set of bytes, forever. Anything else
# — a tag, a `sha-<short>` tag that merely LOOKS reproducible, an empty value —
# is refused here rather than passed through to `docker compose`, because the
# refusal has to happen where somebody reads it.
#
# The all-zero digest is refused BY NAME. It is syntactically a perfect digest
# and names nothing that can ever exist, so a shape check alone would pass it
# and the failure would surface as an inscrutable pull error at deploy time.
#
# Usage:
#     APP_IMAGE="$(scripts/resolve_deploy_image.sh)"   # or the path as $1
#     WORKSPACE_IMAGE="$APP_IMAGE" docker compose up -d

set -euo pipefail

RENDERED_COMPOSE="${1:-${RENDERED_COMPOSE:-deploy/rendered/docker-compose.yml}}"
PLACEHOLDER_DIGEST="sha256:$(printf '0%.0s' $(seq 1 64))"

if [ ! -f "${RENDERED_COMPOSE}" ]; then
  echo "refusing: no rendered compose file at ${RENDERED_COMPOSE}" >&2
  echo "Render it with the pinned facility: make deploy-render" >&2
  exit 1
fi

# The `workspace` service's image, taken from the rendered file rather than from
# the descriptor: the rendered bytes are what CI byte-compares, so reading them
# here means the deploy path and the gate cannot disagree about the answer.
reference="$(
  awk '
    /^  workspace:$/        { in_role = 1; next }
    in_role && /^  [a-z]/   { in_role = 0 }
    in_role && $1 == "image:" {
      value = $2
      gsub(/"/, "", value)
      print value
      exit
    }
  ' "${RENDERED_COMPOSE}"
)"

if [ -z "${reference}" ]; then
  echo "refusing: no image reference for the 'workspace' service in ${RENDERED_COMPOSE}" >&2
  exit 1
fi

if ! printf '%s' "${reference}" | grep -Eq '^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$'; then
  echo "refusing: ${reference} is not pinned by digest." >&2
  echo "The deploy path accepts name@sha256:<64 hex> and nothing else — a tag is" >&2
  echo "a mutable pointer, and 'the image we tested' must not be a different" >&2
  echo "fact from 'the image the host runs'." >&2
  exit 1
fi

if printf '%s' "${reference}" | grep -qF "${PLACEHOLDER_DIGEST}"; then
  echo "refusing: ${reference} is the all-zero PLACEHOLDER digest." >&2
  echo "It parses as a digest and names nothing that can exist. The Workspace" >&2
  echo "has no image publication lane yet, so deploy/product.toml cannot name a" >&2
  echo "candidate this repository derived. Publish a candidate, put its registry" >&2
  echo "digest and source revision in deploy/product.toml, re-render, and arm" >&2
  echo "require-real-digests in .github/workflows/deployment-conformance.yml." >&2
  exit 1
fi

printf '%s\n' "${reference}"
