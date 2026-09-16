from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

import pytest
from scripts.workspace_bundle_producer import BundleError, build_bundle


def _plan(path: Path, filename: str, content: bytes) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "plan_digest": "d" * 64,
                "artifacts": [
                    {
                        "package_normalised_name": "private-package",
                        "filename": filename,
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                ],
            }
        )
    )


def test_build_bundle_contains_only_verified_wheels(tmp_path: Path) -> None:
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    filename = "private_package-1.2.3-py3-none-any.whl"
    content = b"wheel contents"
    (wheels / filename).write_bytes(content)
    plan = tmp_path / "expected.json"
    _plan(plan, filename, content)
    output = tmp_path / "bundle.zip"

    build_bundle(plan, wheels, output)

    with zipfile.ZipFile(output) as bundle:
        assert bundle.namelist() == [filename]
        assert bundle.read(filename) == content


def test_hash_or_extra_file_is_refused(tmp_path: Path) -> None:
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    filename = "private_package-1.2.3-py3-none-any.whl"
    (wheels / filename).write_bytes(b"expected")
    (wheels / "unexpected.whl").write_bytes(b"extra")
    plan = tmp_path / "expected.json"
    _plan(plan, filename, b"expected")

    with pytest.raises(BundleError):
        build_bundle(plan, wheels, tmp_path / "bundle.zip")


def test_symlinked_wheel_is_refused(tmp_path: Path) -> None:
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    filename = "private_package-1.2.3-py3-none-any.whl"
    source = tmp_path / "outside.whl"
    source.write_bytes(b"expected")
    (wheels / filename).symlink_to(source)
    plan = tmp_path / "expected.json"
    _plan(plan, filename, b"expected")

    with pytest.raises(BundleError):
        build_bundle(plan, wheels, tmp_path / "bundle.zip")


def test_cli_failure_does_not_echo_captured_pip_output(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    plan = tmp_path / "expected.json"
    _plan(plan, "private_package-1.2.3-py3-none-any.whl", b"expected")
    from scripts import workspace_bundle_producer

    def fail_download(*args, **kwargs):
        raise subprocess.CalledProcessError(
            1, args[0], output="https://ci-reader:secret@example.invalid", stderr="pip"
        )

    monkeypatch.setattr(workspace_bundle_producer.subprocess, "run", fail_download)

    assert (
        workspace_bundle_producer.main(
            [
                "--plan",
                str(plan),
                "--download-dir",
                str(tmp_path / "wheels"),
                "--output",
                str(tmp_path / "bundle.zip"),
            ]
        )
        == 2
    )
    assert "pip" not in capsys.readouterr().err.lower()


def test_workflow_has_protected_fetch_and_pinned_actions() -> None:
    workflow = Path(".github/workflows/dependency-bundle-producer.yml").read_text()
    assert "workflow_dispatch:" in workflow
    assert "environment: dependency-bundle" in workflow
    assert "persist-credentials: false" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "ref: refs/heads/main" not in workflow
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in workflow
    assert "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97" in workflow
    assert "python-version: '3.12'" in workflow
    assert "secrets.FORGEJO_BUNDLE_READ_TOKEN" in workflow
    assert workflow.count("secrets.") == 1
    assert "secrets.FORGEJO_READ_TOKEN" not in workflow
    assert "FORGEJO_PYPI_TOKEN" not in workflow
    assert "FORGEJO_PYPI_USER" not in workflow
    assert 'if [ -z "$FORGEJO_BUNDLE_READ_TOKEN" ]; then' in workflow
    assert "ci-reader:" in workflow
    assert "upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0" in workflow
    assert (
        "verified-dependency-bundle@7ec614c7b8051e7d399d80381ffdb6344d50dbc6"
        in workflow
    )
    assert "operation: construct" in workflow
    assert (
        "archive-artifact-id: ${{ steps.bundle-upload.outputs.artifact-id }}"
        in workflow
    )
    assert "acquired-dir: wheels" in workflow
    assert "archive-path: bundle.zip" in workflow
    assert "environment-name: dependency-bundle" in workflow
    assert "producer-repository: ${{ github.repository }}" in workflow
    assert "producer-repository-id: ${{ github.repository_id }}" in workflow
    assert (
        "producer-workflow-path: .github/workflows/dependency-bundle-producer.yml"
        in workflow
    )
    assert "archive-artifact-name: workspace-dependency-bundle" in workflow
    assert "sidecar-artifact-name: workspace-dependency-bundle-manifest" in workflow
    assert "steps.manifest.outputs.manifest-path" in workflow
    assert "retention-days: 90" in workflow
    assert "\n          artifact-id:" not in workflow
    assert "output: dependency-bundle-manifest.json" not in workflow
    assert "run: pip" not in workflow
