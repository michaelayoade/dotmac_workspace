from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from scripts import workspace_bundle_install
from scripts.workspace_bundle_install import BundleError, install

FILENAME = "private_package-1.2.3-py3-none-any.whl"
CONTENT = b"verified wheel"


def _expected(path: Path, filename: str = FILENAME, content: bytes = CONTENT) -> None:
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


def _bundle(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "index"
    wheel = root / "simple" / "private-package" / FILENAME
    wheel.parent.mkdir(parents=True)
    wheel.write_bytes(CONTENT)
    expected = tmp_path / "expected.json"
    _expected(expected)
    return expected, root, tmp_path / "python"


def test_install_verifies_and_uses_direct_no_index_wheels(
    tmp_path: Path, monkeypatch
) -> None:
    expected, root, python = _bundle(tmp_path)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        workspace_bundle_install.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command),
    )

    install(expected, root, python)

    assert calls == [
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            str(root / "simple" / "private-package" / FILENAME),
        ]
    ]


@pytest.mark.parametrize("case", ["missing", "extra", "tampered", "symlink"])
def test_invalid_bundle_is_refused(tmp_path: Path, case: str) -> None:
    expected, root, python = _bundle(tmp_path)
    wheel = root / "simple" / "private-package" / FILENAME
    if case == "missing":
        wheel.unlink()
    elif case == "extra":
        extra = root / "simple" / "private-package" / "other-1.0-py3-none-any.whl"
        extra.write_bytes(b"unexpected")
    elif case == "tampered":
        wheel.write_bytes(b"tampered")
    else:
        wheel.unlink()
        wheel.symlink_to(tmp_path / "outside.whl")

    with pytest.raises(BundleError):
        install(expected, root, python)


def test_cli_does_not_echo_pip_failure(tmp_path: Path, capsys, monkeypatch) -> None:
    expected, root, python = _bundle(tmp_path)

    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(
            1, args[0], stderr="https://user:secret@example.invalid"
        )

    monkeypatch.setattr(workspace_bundle_install.subprocess, "run", fail)
    assert (
        workspace_bundle_install.main(
            [
                "--expected-file",
                str(expected),
                "--index-root",
                str(root),
                "--python",
                str(python),
            ]
        )
        == 2
    )
    assert "secret" not in capsys.readouterr().err


def test_from_wheel_boot_uses_bundle_and_no_private_index() -> None:
    script = Path("scripts/from_wheel_boot.sh").read_text()
    assert "BUNDLE_EXPECTED_FILE:?BUNDLE_EXPECTED_FILE is required" in script
    assert "BUNDLE_INDEX_ROOT:?BUNDLE_INDEX_ROOT is required" in script
    assert "workspace_bundle_install.py" in script
    assert "--no-index" not in script
    assert "PIP_EXTRA_INDEX_URL" not in script
