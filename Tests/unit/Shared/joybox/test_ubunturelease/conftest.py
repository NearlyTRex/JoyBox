# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import ubunturelease

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def release_page(monkeypatch):
    state = {"html": ""}
    monkeypatch.setattr(
        ubunturelease.network, "get_remote_html", lambda **kwargs: state["html"])
    return state


@pytest.fixture
def published_checksum(monkeypatch):
    # The listing is fetched and its signature checked before any of it is
    # believed, so this stands in for the whole of that.
    from ubunturelease_helpers import CHECKSUM, image_named
    state = {"checksums": {image_named("24.04.1"): CHECKSUM}}
    monkeypatch.setattr(
        ubunturelease, "fetch_release_checksums", lambda **kwargs: state["checksums"])
    return state


@pytest.fixture
def signature_check(monkeypatch, tmp_path):
    # A keyring on disk, and whatever gpg would have reported
    from ubunturelease_helpers import status_line
    keyring = tmp_path / "keyring.gpg"
    keyring.write_bytes(b"keyring")
    state = {"status": status_line(), "commands": []}

    def run_output_command(cmd, **kwargs):
        state["commands"].append(cmd)
        return state["status"]

    monkeypatch.setattr(
        ubunturelease.programs, "is_tool_installed", lambda name: name == "Gpg")
    monkeypatch.setattr(ubunturelease.programs, "get_tool_program", lambda name: "/tools/gpg")
    monkeypatch.setattr(ubunturelease.command, "run_output_command", run_output_command)
    state["keyring"] = str(keyring)
    return state


@pytest.fixture
def published_files(monkeypatch, tmp_path):
    from ubunturelease_helpers import CHECKSUM, checksum_listing, image_named
    state = {
        "listing": checksum_listing((CHECKSUM, image_named("24.04.1"))),
        "downloaded": [],
        "signature_ok": True,
        "failing": (),
    }

    def download_url(url, output_file, **kwargs):
        state["downloaded"].append(url)
        if url.endswith(state["failing"]):
            return False
        with open(output_file, "w", encoding = "utf-8") as handle:
            handle.write(state["listing"] if url.endswith("SHA256SUMS") else "signature")
        return True

    monkeypatch.setattr(ubunturelease.network, "download_url", download_url)
    monkeypatch.setattr(
        ubunturelease, "verify_checksum_signature", lambda **kwargs: state["signature_ok"])
    return state
