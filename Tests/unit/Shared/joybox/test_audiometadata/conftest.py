# Imports
import importlib
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import audiometadata

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def metadata(monkeypatch):
    # The class loads mutagen from the tool registry, which a hermetic home
    # has no copy of; the installed package stands in for it.
    loaded = iter([
        importlib.import_module(name)
        for name in ("mutagen", "mutagen.mp3", "mutagen.id3", "mutagen.mp4")
    ])
    monkeypatch.setattr(audiometadata.modules, "import_python_module_package",
        lambda module_path, module_name: next(loaded))
    return audiometadata.AudioMetadata()


@pytest.fixture
def mp3_file(tmp_path):
    from audiometadata_helpers import MP3_FRAME
    target = tmp_path / "track.mp3"
    target.write_bytes(MP3_FRAME * 40)
    return str(target)


@pytest.fixture
def m4a_file(tmp_path):
    from audiometadata_helpers import build_m4a
    target = tmp_path / "track.m4a"
    target.write_bytes(build_m4a())
    return str(target)
