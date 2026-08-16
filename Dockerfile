# The Workspace's production image. Multi-stage, non-root, no dev dependencies.
#
# ## The registry credential is a BUILD SECRET, never a build argument
#
# Three `dotmac-*` distributions resolve from the private Forgejo index, which
# needs a credential to read. `ARG` is the obvious way to pass one and it is
# wrong: build arguments are recorded in image metadata, so `docker history`
# hands the token to anyone who can pull the image — including a registry mirror
# nobody remembers configuring.
#
# So the credential arrives through BuildKit's `--mount=type=secret`, which
# exposes it to ONE `RUN` and never writes it to a layer:
#
#     DOCKER_BUILDKIT=1 docker build \
#       --secret id=forgejo_netrc,src=$HOME/.netrc \
#       -t "${IMAGE:-dotmac-workspace}:${TAG:-dev}" .
#
# The `.netrc` form is deliberate over `POETRY_HTTP_BASIC_*` environment
# variables: an env var set for the `RUN` is visible in `/proc` to anything else
# in that layer's build, and it is one careless `RUN env` from a log. A file
# mounted at a path exists for the duration of the command and then does not.
#
# Its contents are an OpenBao-sourced read token — see docs/PILOT-RUNBOOK.md for
# the path. Nothing in this repository ever holds the value.

ARG PYTHON_VERSION=3.12

# ── build ───────────────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=1.8.3 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_NO_INTERACTION=1

RUN pip install "poetry==${POETRY_VERSION}"

WORKDIR /app

# Dependency manifests first, so a source-only change reuses the resolved layer.
# README.md comes along because `pyproject.toml` declares `readme = "README.md"`.
# Without it poetry cannot build the project metadata and the root install
# becomes a silent no-op: the image ships every dependency and NOT the
# application, with `ModuleNotFoundError` from a running container as the only
# symptom. Found on the first real deployment.
COPY pyproject.toml poetry.lock README.md ./

# `--only main` drops the dev group: pytest, ruff, mypy and the pyjwt the TESTS
# use to mint ID tokens have no business in a production image. The runtime gets
# pyjwt transitively through dotmac-auth-oidc, at that package's security floor.
#
# `--no-root` because the project itself is installed after the source is
# copied; installing it here would bake a stale copy into the dependency layer.
RUN --mount=type=secret,id=forgejo_netrc,target=/root/.netrc,mode=0400 \
    poetry install --without dev --no-root

COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./

RUN --mount=type=secret,id=forgejo_netrc,target=/root/.netrc,mode=0400 \
    poetry install --without dev \
 && /app/.venv/bin/python -c "import dotmac_workspace" \
 && echo "the application is importable from the venv"

# ── runtime ─────────────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

# Non-root, with a fixed uid so a bind-mounted volume's ownership is
# predictable rather than whatever the daemon assigned this build.
RUN groupadd --system --gid 10001 workspace \
    && useradd --system --uid 10001 --gid workspace --no-create-home workspace

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY --from=build --chown=root:root /app/.venv /app/.venv
COPY --from=build --chown=root:root /app/src /app/src
COPY --from=build --chown=root:root /app/alembic /app/alembic
COPY --from=build --chown=root:root /app/alembic.ini /app/alembic.ini

# Owned by root, run as workspace: the process can read its own code and cannot
# rewrite it. A compromised request handler that can patch the app on disk turns
# one bug into persistence.
USER workspace

# The check that would have caught an image shipping without its application.
# At BUILD time, so a broken image is never tagged — as opposed to never
# starting, which is what a healthcheck gives you after the fact.
RUN python -c "import dotmac_workspace, dotmac_kernel, dotmac_auth_oidc; \
print('runtime imports ok:', dotmac_workspace.__name__)"

# Every value overridable, with a documented default (AGENTS.md § everything by
# config). PORT is the only one the image itself needs.
ENV PORT=8000
EXPOSE 8000

# NO MIGRATIONS ON BOOT. The container runs as the online role, which cannot
# issue DDL; migrations run as the admin role from the deploy path, once, before
# the new image starts. A boot-time upgrade also means N replicas racing to
# apply the same revision. Same rule as the starter's hard rule 13.
#
# `--proxy-headers` with `--forwarded-allow-ips` from configuration: the
# Workspace sets `Secure` on its cookies from `is_secure_request`, which reads
# the forwarded scheme, so trusting the wrong proxy makes that decision wrong.
CMD ["sh", "-c", "exec uvicorn dotmac_workspace.main:app \
    --host 0.0.0.0 --port ${PORT} \
    --proxy-headers --forwarded-allow-ips=\"${FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
