"""The deployment artefact says what it means, and holds no deployment's name.

The Workspace adopts `dotmac-deployment-foundation` (Starter ADR-0070) as
DECLARATIVE INPUT plus a CI gate — not as the deployment engine. `deploy/README.md`
draws that boundary; this module is what keeps it from eroding.

Five properties, each with a defect behind it:

1. **The artefact is host-neutral.** `deploy/product.toml` names a reserved,
   permanently non-resolvable ingress host, and no deployment artefact carries a
   real host name. One artefact that names one deployment is not reusable, and a
   host name committed to Git is a fact about the world that nothing here can
   keep true. The real host arrives at authorization time from the environment
   inventory.

2. **The guards bite.** Both host-neutrality checks are re-run over a tree with
   `workspace.dotmac.io` deliberately PLANTED in it, and are required to report
   it. A detector that has never been observed to fire is not a control; it is a
   line in a file that everyone after this will read as one. (ADR-0018: a
   detector carries a sensitivity proof.)

3. **The version is stated once.** `pyproject.toml` and the conformance workflow
   pin the same exact facility release, and the reusable gate is pinned by
   immutable commit rather than by a mutable tag or branch.

4. **The placeholder exemption states an enforceable premise.**
   `require-real-digests: false` is legitimate only while the descriptor's image
   really is the all-zero placeholder. The ratchet fails in BOTH directions —
   a real digest with the gate still off, and the gate off while the digest is
   real. ERP left exactly this flag off after its own sentinel was replaced, and
   nothing noticed: an all-zero digest PARSES.

5. **The deploy path cannot run a tag.** No `:latest`, no `WORKSPACE_TAG`, no
   default. `scripts/resolve_deploy_image.sh` is the only supported source of
   the image reference and it refuses anything that is not a digest.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tomllib
from collections.abc import Iterable
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DESCRIPTOR = REPO / "deploy" / "product.toml"
MANIFEST = REPO / "deploy" / "product-manifest.json"
RENDERED = REPO / "deploy" / "rendered"
CONFORMANCE_WORKFLOW = REPO / ".github" / "workflows" / "deployment-conformance.yml"
ROOT_COMPOSE = REPO / "docker-compose.yml"

PLACEHOLDER_DIGEST = "sha256:" + "0" * 64

# RFC 2606 §2 and RFC 6761: reserved names that can never resolve on the public
# internet. A fixture host under one of these cannot be installed by accident,
# which is precisely what makes it safe to commit.
RESERVED_TLDS = ("invalid", "test", "example", "localhost")

# The TLDs the scanner recognises as naming a REAL host. Deliberately a closed
# list rather than "any dotted token": `dotmac_workspace.main:app` and
# `alembic.ini` are dotted too, and a scanner that flagged them would be turned
# off within a week. The cost is that a hostname under an unlisted TLD escapes;
# the sensitivity proof below uses the actual production host, which does not.
REAL_TLDS = ("io", "com", "net", "org", "ng", "dev", "app", "internal", "local")

_HOST = re.compile(
    r"\b([a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+)\b"
)

# The one real host a deployment ARTEFACT may name, and why: the image has to
# come from somewhere, and the registry is fleet infrastructure rather than a
# deployment's public identity. Nothing else belongs here — adding a name to
# this list is the reviewable moment this guard exists to create.
PERMITTED_REAL_HOSTS = frozenset({"registry.dotmac.io"})

# The deployment ARTEFACTS: the files that describe or become a running
# deployment. Enumerated positively so a new artefact is added deliberately.
#
# `*.md` and `.env.example` are NOT here, and that is a boundary rather than an
# oversight: a runbook that tells an operator to type `workspace.dotmac.io`, and
# an example file showing the shape of the value they must supply, are the
# INSTRUCTION to supply a host. They are not the artefact that carries one, and
# scrubbing them would only move the knowledge somewhere less reviewable.
ARTEFACT_FILES = (
    "deploy/product.toml",
    "deploy/product-manifest.json",
    "deploy/alerts/thresholds.json",
    "deploy/nginx/workspace.conf.template",
    "docker-compose.yml",
    "Makefile",
)
ARTEFACT_TREES = ("deploy/rendered",)


def _descriptor() -> dict:
    return tomllib.loads(DESCRIPTOR.read_text(encoding="utf-8"))


def _workflow_text() -> str:
    return CONFORMANCE_WORKFLOW.read_text(encoding="utf-8")


def _artefact_paths(root: Path) -> list[Path]:
    paths = [root / name for name in ARTEFACT_FILES]
    for tree in ARTEFACT_TREES:
        paths.extend(sorted(p for p in (root / tree).rglob("*") if p.is_file()))
    return [p for p in paths if p.is_file()]


def _real_hosts_in(paths: Iterable[Path], root: Path) -> dict[str, list[str]]:
    """Every REAL host name each artefact names, keyed by relative path.

    The one detector, called by both the real check and its sensitivity proof,
    so the proof cannot pass against a different implementation from the one
    that guards the repository.
    """
    found: dict[str, list[str]] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        hits = sorted(
            {
                match.group(1)
                for match in _HOST.finditer(text)
                if match.group(1).rsplit(".", 1)[-1] in REAL_TLDS
                and match.group(1) not in PERMITTED_REAL_HOSTS
            }
        )
        if hits:
            found[str(path.relative_to(root))] = hits
    return found


def test_the_ingress_host_is_a_reserved_non_resolvable_name() -> None:
    """The descriptor's vhost source names no deployment.

    `[ingress].host` is rendered into `server_name` and into the certificate
    paths, and it names the file the render is written to. A production host
    here would make this artefact permanently about one deployment — and would
    put a live host name in Git, where nothing can keep it true.
    """
    host = _descriptor()["ingress"]["host"]
    assert host.rsplit(".", 1)[-1] in RESERVED_TLDS, (
        f"[ingress].host is {host!r}, which is a resolvable name. It must sit "
        f"under a reserved TLD ({', '.join(RESERVED_TLDS)}) so the committed "
        "vhost cannot be installed by accident; the deployment's real host is "
        "supplied at authorization time by the environment inventory."
    )
    # Non-vacuity: the rendered vhost is actually named after it, so a change to
    # the descriptor that did not re-render would be caught here too.
    assert (RENDERED / "nginx" / f"{host}.conf").is_file()


def test_no_deployment_artefact_names_a_real_deployment_host() -> None:
    """No artefact carries a live host name."""
    offenders = _real_hosts_in(_artefact_paths(REPO), REPO)
    assert not offenders, (
        "deployment artefact(s) name a real host: "
        + "; ".join(f"{path}: {', '.join(hosts)}" for path, hosts in offenders.items())
        + ". A deployment's public identity is supplied at authorization time "
        "from the environment inventory, never committed here."
    )


def test_the_scanner_actually_reads_the_artefacts() -> None:
    """A check over an empty set passes for the wrong reason.

    `test_no_deployment_artefact_names_a_real_deployment_host` would be green if
    `ARTEFACT_FILES` were misspelled, if `deploy/rendered` were renamed, or if
    the regex matched nothing at all. This pins the floor: the files exist, the
    rendered tree is in scope, and the detector demonstrably matches host-shaped
    text in them.
    """
    paths = _artefact_paths(REPO)
    names = {str(p.relative_to(REPO)) for p in paths}
    assert set(ARTEFACT_FILES) <= names
    assert any(name.startswith("deploy/rendered/") for name in names)

    all_hosts = {
        match.group(1)
        for path in paths
        for match in _HOST.finditer(path.read_text(encoding="utf-8", errors="ignore"))
    }
    assert "registry.dotmac.io" in all_hosts, (
        "the detector matched no host in the rendered compose file, so its "
        "silence about production hosts means nothing"
    )
    assert _descriptor()["ingress"]["host"] in all_hosts


def test_the_hostname_guard_bites(tmp_path: Path) -> None:
    """PLANT a production host, and require the guard to report it.

    Run against a copy so the repository is never modified. If this ever passes
    without the plant being found, the guard above is decoration.
    """
    planted = tmp_path / "repo"
    (planted / "deploy" / "rendered" / "nginx").mkdir(parents=True)
    (planted / "deploy" / "alerts").mkdir(parents=True)
    (planted / "deploy" / "nginx").mkdir(parents=True)
    for name in ARTEFACT_FILES:
        shutil.copyfile(REPO / name, planted / name)
    shutil.copytree(RENDERED, planted / "deploy" / "rendered", dirs_exist_ok=True)

    # Clean copy first: the proof is only meaningful if the guard is silent
    # about the real tree and loud about the planted one.
    assert not _real_hosts_in(_artefact_paths(planted), planted)

    victim = planted / "deploy" / "product.toml"
    victim.write_text(
        victim.read_text(encoding="utf-8").replace(
            'host = "workspace.fixture.invalid"', 'host = "workspace.dotmac.io"'
        ),
        encoding="utf-8",
    )
    offenders = _real_hosts_in(_artefact_paths(planted), planted)
    assert offenders.get("deploy/product.toml") == ["workspace.dotmac.io"], (
        "a planted production hostname was NOT reported; the host-neutrality "
        f"guard does not bite. reported: {offenders!r}"
    )


def test_the_reserved_tld_check_bites() -> None:
    """The ingress-host check refuses a real name.

    Same reasoning as above, for the other half of host-neutrality: the property
    is checked by reading a value, so the proof is that a real value fails it.
    """
    for real in ("workspace.dotmac.io", "ws.example.com", "workspace.dotmac.ng"):
        assert real.rsplit(".", 1)[-1] not in RESERVED_TLDS
    assert "workspace.fixture.invalid".rsplit(".", 1)[-1] in RESERVED_TLDS


def test_the_pinned_foundation_version_is_stated_once() -> None:
    """`pyproject.toml` and the CI gate pin the same exact release.

    Two pins that can disagree are one pin and one lie. The gate installs what
    it is told; a local `make deploy-render` uses what poetry installed. If those
    differ, the committed bytes were produced by a version CI never runs.
    """
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    dev = project["tool"]["poetry"]["group"]["dev"]["dependencies"]
    pinned = dev["dotmac-deployment-foundation"]["version"]

    match = re.search(r'foundation-version:\s*"([^"]+)"', _workflow_text())
    assert match, "the conformance workflow states no foundation-version"
    assert match.group(1) == pinned, (
        f"pyproject pins {pinned!r} and the conformance gate installs "
        f"{match.group(1)!r}"
    )
    # A range is refused by the reusable gate itself; refuse it here too, where
    # the message can say why.
    assert re.fullmatch(r"\d+\.\d+\.\d+([ab]\d+)?", pinned), (
        f"{pinned!r} is not an exact version. A gate that resolves to 'whatever "
        "is newest' cannot tell a product that drifted from a foundation that "
        "changed."
    )


def test_the_reusable_gate_is_pinned_to_an_immutable_commit() -> None:
    """`uses: …@<40-hex>`, never a tag or a branch.

    A tag is mutable, so a pin to one is a pin to whatever that name points at
    today — and the whole point of the pin is that CI executes the revision that
    was reviewed.
    """
    match = re.search(
        r"uses:\s*michaelayoade/dotmac_starter_mt/\.github/workflows/"
        r"deployment-conformance\.yml@(\S+)",
        _workflow_text(),
    )
    assert match, "the conformance workflow does not call the Starter gate"
    assert re.fullmatch(r"[0-9a-f]{40}", match.group(1)), (
        f"the reusable gate is pinned to {match.group(1)!r}, which is not a "
        "40-character commit sha"
    )


def test_the_placeholder_exemption_states_an_enforceable_premise() -> None:
    """`require-real-digests` and the descriptor's digest move together.

    A two-directional ratchet. The exemption is legitimate ONLY while the image
    really is the all-zero placeholder; the moment a candidate digest lands, the
    gate must be armed, and the gate may not be disarmed while the digest is
    real.
    """
    image = _descriptor()["image"]["reference"]
    is_placeholder = image.endswith(PLACEHOLDER_DIGEST)

    match = re.search(r"require-real-digests:\s*(true|false)", _workflow_text())
    assert match, "the conformance workflow does not state require-real-digests"
    armed = match.group(1) == "true"

    if is_placeholder:
        assert not armed, (
            "the descriptor pins the all-zero placeholder while the conformance "
            "gate requires real digests; the gate cannot pass, so one of the two "
            "is wrong"
        )
    else:
        assert armed, (
            f"the descriptor pins a real image digest ({image}) while "
            "require-real-digests is off. Arm it: with the gate off, nothing at "
            "all prevents a silent regression back to a placeholder, because an "
            "all-zero digest parses."
        )

    # The manifest digest is real either way — the exemption covers the image
    # only, and `check_no_placeholder_digests` would otherwise be suppressing a
    # second finding nobody decided about.
    assert _descriptor()["assembly"]["manifest_digest"] != PLACEHOLDER_DIGEST


def test_the_assembly_manifest_digest_is_the_digest_of_the_committed_bytes() -> None:
    """The approved module set is identified by its own bytes."""
    raw = MANIFEST.read_bytes()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    assert _descriptor()["assembly"]["manifest_digest"] == digest, (
        "deploy/product-manifest.json changed without deploy/product.toml's "
        "manifest_digest moving with it"
    )
    # Canonical, so two renders of the same module set cannot differ in bytes.
    manifest = json.loads(raw)
    assert raw.decode("utf-8") == json.dumps(
        manifest, sort_keys=True, separators=(",", ":")
    )


def test_the_manifest_names_the_versions_this_assembly_actually_pins() -> None:
    """The approved module set is the installed one.

    A manifest that drifts from `pyproject.toml` describes a deployment nobody
    is running, and `dotmac-deploy drift` would then be comparing against it.
    """
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    pins = project["tool"]["poetry"]["dependencies"]
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["product"] == _descriptor()["product"]
    for module in manifest["modules"]:
        declared = pins[module["distribution"]]["version"]
        assert module["version"] == declared, (
            f"{module['distribution']} is pinned at {declared} and the product "
            f"manifest says {module['version']}"
        )


def test_the_deploy_path_cannot_run_a_tag() -> None:
    """`:latest` is unreachable, and there is no default to fall back to."""
    compose = ROOT_COMPOSE.read_text(encoding="utf-8")
    image_lines = [
        line.strip()
        for line in compose.splitlines()
        if line.strip().startswith("image:")
    ]
    assert len(image_lines) == 1, (
        f"the deployed compose file declares {len(image_lines)} image line(s); "
        "one service, one image"
    )
    line = image_lines[0]
    # `:?` — required, with no default. `:-` would reintroduce the floating
    # reference under a different name.
    assert line.startswith("image: ${WORKSPACE_IMAGE:?"), (
        f"the image line is {line!r}. It must be ${{WORKSPACE_IMAGE:?…}}: a "
        "single required variable, with no tag and no default to fall back on."
    )
    assert ":latest" not in line and ":-" not in line

    # Retired, and checked on the EFFECTIVE lines only. Both files explain in a
    # comment what the variable used to do and why it is gone; deleting that
    # history to satisfy a substring search would cost the next reader the
    # reason. What must not come back is a line that READS it.
    for path in (ROOT_COMPOSE, REPO / ".env.example"):
        effective = [
            stripped
            for raw in path.read_text(encoding="utf-8").splitlines()
            if (stripped := raw.strip()) and not stripped.startswith("#")
        ]
        assert not [row for row in effective if "WORKSPACE_TAG" in row], (
            f"{path.name} still reads WORKSPACE_TAG. It defaulted to `latest`, "
            "and a tag is a mutable registry pointer: the bytes it names can be "
            "replaced after they were tested."
        )

    resolver = (REPO / "scripts" / "resolve_deploy_image.sh").read_text(
        encoding="utf-8"
    )
    assert "@sha256:[0-9a-f]{64}$" in resolver
    assert "PLACEHOLDER_DIGEST" in resolver


def test_the_rendered_compose_runs_the_digest_the_descriptor_names() -> None:
    """One authority for which image runs."""
    rendered = (RENDERED / "docker-compose.yml").read_text(encoding="utf-8")
    reference = _descriptor()["image"]["reference"]
    assert f'image: "{reference}"' in rendered


def test_expected_heads_name_this_assemblys_own_revision() -> None:
    """The declared heads include the revision this repository owns.

    The other two belong to installed packages and move with their pins; this
    one is in the tree, so it is the one a local edit can silently orphan.
    """
    heads = _descriptor()["migration"]["expected_heads"]
    own = [
        re.search(r'^revision = "([^"]+)"', text, re.MULTILINE)
        for text in (
            path.read_text(encoding="utf-8")
            for path in (REPO / "alembic" / "versions").glob("*.py")
        )
    ]
    revisions = {match.group(1) for match in own if match}
    assert revisions, "no assembly migration revisions were found"
    assert revisions <= set(heads), (
        f"assembly revision(s) {sorted(revisions - set(heads))} are not in the "
        "descriptor's expected_heads"
    )


@pytest.mark.parametrize(
    "asset", ["docker-compose.yml", "alerts.rules.yml", "otel-collector.yaml"]
)
def test_every_rendered_asset_says_it_is_generated(asset: str) -> None:
    """A rendered file a reader might hand-edit says not to, in its first lines."""
    head = (RENDERED / asset).read_text(encoding="utf-8")[:600]
    assert "GENERATED by dotmac-deployment-foundation" in head


def test_the_descriptor_passes_the_pinned_facilitys_own_checks() -> None:
    """The gate's verdict, reproduced in the DB-free suite.

    The conformance workflow is the acceptance owner; this is the same question
    asked where a developer sees it in a second, and it is what makes the
    placeholder exemption above verifiable rather than asserted — the ONLY
    finding it is allowed to suppress is the one `check_no_placeholder_digests`
    returns.
    """
    # Imported here rather than skipped-if-missing: it is a locked dev
    # dependency, so an ImportError means the environment is wrong, and a check
    # that quietly skips itself is an unmonitored region rather than an exempt
    # one (ADR-0018).
    from dotmac_deployment_foundation.conformance import (
        check_all,
        check_no_placeholder_digests,
    )
    from dotmac_deployment_foundation.spec import ProductDeploymentSpec

    spec = ProductDeploymentSpec.load(DESCRIPTOR)
    findings = check_all(spec)
    permitted = check_no_placeholder_digests(spec)
    for finding in permitted:
        findings.remove(finding)
    assert findings == [], findings
