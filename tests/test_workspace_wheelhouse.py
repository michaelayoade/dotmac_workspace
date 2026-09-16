from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest
from scripts import workspace_wheelhouse as wheelhouse

PRIVATE = "private_package-1.0-py3-none-any.whl"
PUBLIC = "public_package-2.0-py3-none-any.whl"


def _inputs(tmp_path: Path) -> tuple[Path, Path, dict[str, bytes]]:
    contents = {PRIVATE: b"private wheel", PUBLIC: b"public wheel"}
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[tool.poetry.dependencies]\npython = ">=3.12,<3.14"\n'
        'private-package = {version = "1.0", source = "forgejo"}\n'
    )
    lock = tmp_path / "poetry.lock"
    private_hash = hashlib.sha256(contents[PRIVATE]).hexdigest()
    public_hash = hashlib.sha256(contents[PUBLIC]).hexdigest()
    lock.write_text(
        '[[package]]\nname = "private-package"\nversion = "1.0"\n'
        f'files = [{{file = "{PRIVATE}", hash = "sha256:{private_hash}"}}]\n'
        "[package.source]\n"
        'type = "legacy"\n'
        f'url = "{wheelhouse.PRIVATE_INDEX}"\n'
        'reference = "forgejo"\n\n'
        '[[package]]\nname = "public-package"\nversion = "2.0"\n'
        f'files = [{{file = "{PUBLIC}", hash = "sha256:{public_hash}"}}]\n'
    )
    return manifest, lock, contents


def test_real_lock_has_a_complete_private_and_public_wheel_plan() -> None:
    root = Path(__file__).resolve().parents[1]
    plan = wheelhouse.load_plan(root / "pyproject.toml", root / "poetry.lock")
    assert len(plan) == 57
    assert {name for name, item in plan.items() if item["registry"] == "private"} == {
        "dotmac-kernel",
        "dotmac-application-directory",
        "dotmac-auth-oidc",
        "dotmac-ui",
    }


def test_verify_accepts_only_exact_locked_wheels(tmp_path: Path) -> None:
    manifest, lock, contents = _inputs(tmp_path)
    plan = wheelhouse.load_plan(manifest, lock)
    directory = tmp_path / "wheels"
    directory.mkdir()
    for filename, data in contents.items():
        (directory / filename).write_bytes(data)
    assert set(wheelhouse.verify(plan, directory)) == {
        "private-package",
        "public-package",
    }

    (directory / PUBLIC).write_bytes(b"tampered")
    with pytest.raises(wheelhouse.WheelhouseError, match="hash"):
        wheelhouse.verify(plan, directory)
    (directory / PUBLIC).write_bytes(contents[PUBLIC])

    extra = directory / "extra.whl"
    extra.write_bytes(b"extra")
    with pytest.raises(wheelhouse.WheelhouseError, match="extra"):
        wheelhouse.verify(plan, directory)
    extra.unlink()

    (directory / PUBLIC).unlink()
    with pytest.raises(wheelhouse.WheelhouseError, match="missing"):
        wheelhouse.verify(plan, directory)
    (directory / PUBLIC).symlink_to(tmp_path / "outside")
    with pytest.raises(wheelhouse.WheelhouseError, match="link"):
        wheelhouse.verify(plan, directory)


def test_source_drift_and_unlocked_private_package_fail(tmp_path: Path) -> None:
    manifest, lock, _ = _inputs(tmp_path)
    original = lock.read_text()
    lock.write_text(
        original.replace(wheelhouse.PRIVATE_INDEX, "https://other.invalid/simple")
    )
    with pytest.raises(wheelhouse.WheelhouseError, match="source"):
        wheelhouse.load_plan(manifest, lock)
    lock.write_text(
        original.replace('name = "public-package"', 'name = "private-other"').replace(
            'version = "2.0"\nfiles',
            'version = "2.0"\nsource = {type = "legacy", '
            f'url = "{wheelhouse.PRIVATE_INDEX}", '
            'reference = "forgejo"}\nfiles',
        )
    )
    with pytest.raises(wheelhouse.WheelhouseError):
        wheelhouse.load_plan(manifest, lock)


def test_warm_verifies_downloads_and_never_relays_pip_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest, lock, contents = _inputs(tmp_path)
    plan = wheelhouse.load_plan(manifest, lock)
    monkeypatch.setenv(
        "FORGEJO_BUNDLE_READ_TOKEN",
        "SENTINEL_NOT_A_TOKEN",
    )
    monkeypatch.setenv("PIP_TRUSTED_HOST", "ambient-trusted-host")
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "https://ambient.invalid/simple")
    monkeypatch.setenv("HTTP_PROXY", "http://ambient.invalid:8080")

    def download(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        package = command[-1].split("==")[0]
        if package == "private-package":
            child_env = kwargs["env"]
            assert "SENTINEL_NOT_A_TOKEN" in child_env["PIP_INDEX_URL"]
            assert child_env["PIP_INDEX_URL"].startswith("https://ci-reader:")
            assert child_env["PIP_CONFIG_FILE"] == "/dev/null"
            assert "PIP_TRUSTED_HOST" not in child_env
            assert "PIP_EXTRA_INDEX_URL" not in child_env
            assert "HTTP_PROXY" not in child_env
            assert "FORGEJO_BUNDLE_READ_TOKEN" not in child_env
        filename = PRIVATE if package == "private-package" else PUBLIC
        Path(command[command.index("--dest") + 1], filename).write_bytes(
            contents[filename]
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(wheelhouse.subprocess, "run", download)
    directory = tmp_path / "wheels"
    wheelhouse.warm(plan, directory)
    assert len(wheelhouse.verify(plan, directory)) == 2

    def fail(command: list[str], **kwargs: object) -> None:
        raise subprocess.CalledProcessError(
            1,
            command,
            stderr=b"https://ci-reader:SENTINEL_NOT_A_TOKEN@registry.dotmac.io",
        )

    monkeypatch.setattr(wheelhouse.subprocess, "run", fail)
    assert (
        wheelhouse.main(
            [
                "warm",
                "--manifest",
                str(manifest),
                "--lock",
                str(lock),
                "--directory",
                str(tmp_path / "failed"),
            ]
        )
        == 2
    )
    assert "SENTINEL_NOT_A_TOKEN" not in capsys.readouterr().err


def test_warm_quotes_reserved_token_characters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, lock, contents = _inputs(tmp_path)
    plan = wheelhouse.load_plan(manifest, lock)
    monkeypatch.setenv("FORGEJO_BUNDLE_READ_TOKEN", "tok/@?#[ ]")

    def download(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        package = command[-1].split("==")[0]
        if package == "private-package":
            assert kwargs["env"]["PIP_INDEX_URL"].endswith(
                "tok%2F%40%3F%23%5B%20%5D@registry.dotmac.io/api/packages/dotmac/pypi/simple"
            )
        filename = PRIVATE if package == "private-package" else PUBLIC
        Path(command[command.index("--dest") + 1], filename).write_bytes(
            contents[filename]
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(wheelhouse.subprocess, "run", download)
    wheelhouse.warm(plan, tmp_path / "wheels")


def test_warm_refuses_unencoded_reserved_token_before_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, lock, _ = _inputs(tmp_path)
    plan = wheelhouse.load_plan(manifest, lock)
    token = "slash/token"
    monkeypatch.setenv("FORGEJO_BUNDLE_READ_TOKEN", token)
    monkeypatch.setattr(wheelhouse, "quote", lambda value, safe="": value)
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(wheelhouse.subprocess, "run", run)
    with pytest.raises(
        wheelhouse.WheelhouseError, match="credential unavailable"
    ) as error:
        wheelhouse.warm(plan, tmp_path / "wheels")
    assert token not in str(error.value)
    assert calls == []


def test_install_is_index_free_after_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, lock, contents = _inputs(tmp_path)
    plan = wheelhouse.load_plan(manifest, lock)
    directory = tmp_path / "wheels"
    directory.mkdir()
    for filename, data in contents.items():
        (directory / filename).write_bytes(data)
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(wheelhouse.subprocess, "run", run)
    (directory / PUBLIC).write_bytes(b"tampered")
    with pytest.raises(wheelhouse.WheelhouseError, match="hash"):
        wheelhouse.install(plan, directory, Path("/venv/bin/python"))
    assert calls == []
    (directory / PUBLIC).write_bytes(contents[PUBLIC])
    (directory / PUBLIC).unlink()
    with pytest.raises(wheelhouse.WheelhouseError, match="missing"):
        wheelhouse.install(plan, directory, Path("/venv/bin/python"))
    assert calls == []
    (directory / PUBLIC).write_bytes(contents[PUBLIC])
    (directory / "extra.whl").write_bytes(b"extra")
    with pytest.raises(wheelhouse.WheelhouseError, match="extra"):
        wheelhouse.install(plan, directory, Path("/venv/bin/python"))
    assert calls == []
    (directory / "extra.whl").unlink()
    wheelhouse.install(plan, directory, Path("/venv/bin/python"))
    assert calls[0][:4] == ["/venv/bin/python", "-m", "pip", "install"]
    assert "--no-index" in calls[0]
    assert "--find-links" in calls[0]
    assert "--no-deps" in calls[0]
    assert calls[1][-1] == "check"
