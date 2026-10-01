# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox.stores import gog


###########################################################
# Downloading
#
# The fake runner lays out what LGOGDownloader would leave in the temporary
# directory; moving it into place uses the real file operations.
###########################################################

DOWNLOADED = {
    "setup_the_witcher.exe": "game",
    "extra/manual.pdf": "manual",
    "dlc/setup_the_witcher_dlc.exe": "dlc",
    "dlc/extra/soundtrack.zip": "soundtrack",
}


@pytest.fixture
def lgog(gog_store, tools, temp_dir, monkeypatch):
    state = {"files": dict(DOWNLOADED), "code": 0, "calls": []}

    def run_returncode_command(cmd, options = None, **kwargs):
        state["calls"].append((list(cmd), options, kwargs))
        for relative, text in state["files"].items():
            path = temp_dir["path"] / relative
            path.parent.mkdir(parents = True, exist_ok = True)
            path.write_text(text)
        return state["code"]
    monkeypatch.setattr(gog.command, "run_returncode_command", run_returncode_command)
    return state


def listing(root):
    found = []
    for base, _, files in os.walk(root):
        for name in files:
            found.append(os.path.relpath(os.path.join(base, name), root).replace(os.sep, "/"))
    return sorted(found)


def test_a_download_is_moved_into_place(gog_store, lgog, temp_dir, tmp_path):
    output = tmp_path / "out"

    assert gog_store.download("the_witcher", str(output)) is True

    assert listing(output) == [
        "dlc/setup_the_witcher_dlc.exe",
        "extra/manual.pdf",
        "extra/soundtrack.zip",
        "setup_the_witcher.exe"]
    assert not temp_dir["path"].exists()


def test_the_download_command_names_one_game(gog_store, lgog, temp_dir, tmp_path):
    gog_store.download("the_witcher", str(tmp_path / "out"))

    cmd, options, _ = lgog["calls"][0]
    assert cmd == [
        "/tools/lgogdownloader",
        "--download",
        "--game=^the_witcher$",
        "--platform=windows",
        "--directory=%s" % temp_dir["path"],
        "--check-free-space",
        "--threads=1",
        "--subdir-game=.",
        "--subdir-extras=extra",
        "--subdir-dlc=dlc"]
    assert options.get_blocking_processes() == ["/tools/lgogdownloader"]


def test_includes_and_excludes_are_passed_when_set(gog_store, lgog, tmp_path):
    gog_store.includes = "i,e"
    gog_store.excludes = "p"

    gog_store.download("the_witcher", str(tmp_path / "out"))

    cmd = lgog["calls"][0][0]
    assert cmd[-2:] == ["--include=i,e", "--exclude=p"]


def test_a_dlc_extra_that_exists_in_the_main_extra_is_kept_as_is(gog_store, lgog, tmp_path):
    lgog["files"]["dlc/extra/manual.pdf"] = "dlc manual"
    output = tmp_path / "out"

    gog_store.download("the_witcher", str(output))

    assert (output / "extra" / "manual.pdf").read_text() == "manual"
    assert not (output / "dlc" / "extra").exists()


def test_a_download_without_dlc_extras_moves_as_is(gog_store, lgog, tmp_path):
    lgog["files"] = {"setup_the_witcher.exe": "game"}
    output = tmp_path / "out"

    assert gog_store.download("the_witcher", str(output)) is True
    assert listing(output) == ["setup_the_witcher.exe"]


def test_clean_output_clears_old_files_first(gog_store, lgog, tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / "old_setup.exe").write_text("old")

    gog_store.download("the_witcher", str(output), clean_output = True)

    assert "old_setup.exe" not in listing(output)


def test_existing_output_is_kept_without_clean_output(gog_store, lgog, tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / "old_setup.exe").write_text("old")

    gog_store.download("the_witcher", str(output))

    assert "old_setup.exe" in listing(output)


def test_move_options_are_passed_through(gog_store, lgog, monkeypatch, tmp_path):
    moves = []

    def move_contents(src, dest, **kwargs):
        moves.append((src, dest, kwargs))
        return True
    monkeypatch.setattr(gog.fileops, "move_contents", move_contents)

    gog_store.download("the_witcher", str(tmp_path / "out"), show_progress = True, skip_existing = True, skip_identical = True)

    final = moves[-1][2]
    assert (final["show_progress"], final["skip_existing"], final["skip_identical"]) == (True, True, True)


def test_a_failed_download_removes_its_temp(gog_store, lgog, temp_dir, tmp_path):
    lgog["code"] = 1
    output = tmp_path / "out"

    assert gog_store.download("the_witcher", str(output)) is False
    assert not temp_dir["path"].exists()
    assert not output.exists()


def test_a_failed_move_removes_its_temp(gog_store, lgog, temp_dir, monkeypatch, tmp_path):
    monkeypatch.setattr(gog.fileops, "move_contents", lambda **kwargs: False)

    assert gog_store.download("the_witcher", str(tmp_path / "out")) is False
    assert not temp_dir["path"].exists()


def test_a_download_that_produced_nothing_fails(gog_store, lgog, tmp_path):
    lgog["files"] = {}
    output = tmp_path / "out"
    output.mkdir()

    assert gog_store.download("the_witcher", str(output)) is False


def test_a_download_needs_a_temp_directory(gog_store, lgog, temp_dir, tmp_path):
    temp_dir["ok"] = False

    assert gog_store.download("the_witcher", str(tmp_path / "out")) is False
    assert lgog["calls"] == []


def test_a_download_needs_lgogdownloader(gog_store, lgog, tools, temp_dir, tmp_path):
    del tools["programs"]["LGOGDownloader"]

    assert gog_store.download("the_witcher", str(tmp_path / "out")) is False
    assert lgog["calls"] == []
    assert temp_dir["created"] == 0


def test_an_invalid_download_identifier_runs_nothing(gog_store, lgog, tmp_path):
    assert gog_store.download("", str(tmp_path / "out")) is False
    assert lgog["calls"] == []
