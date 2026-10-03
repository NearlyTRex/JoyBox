# Imports
import json
import os
import runpy
import sys
from typing import ClassVar

# Third-party imports
import pytest

# Local imports
from joybox import config, system
from joybox.cli import verify_game_files


###########################################################
# Cross-checks
#
# Every JSON file needs a game directory, every file a JSON or hash file names
# must exist, and the first mismatch stops the run with a non-zero exit.
###########################################################

SWITCH = (config.Supercategory.ROMS, config.Category.NINTENDO, config.Subcategory.NINTENDO_SWITCH)


class FakeGameInfo:

    games: ClassVar[dict] = {}

    def __init__(self, json_file, verbose = False, pretend_run = False, exit_on_failure = False):
        self.data = FakeGameInfo.games[os.path.basename(json_file)[:-len(".json")]]

    def get_files(self):
        return self.data.get("files", [])

    def get_launch_file(self):
        return self.data.get("launch_file")

    def get_transform_file(self):
        return self.data.get("transform_file")


class FakeMetadata:

    verified: ClassVar[list] = []

    def import_from_metadata_file(self, metadata_file):
        self.metadata_file = metadata_file

    def verify_files(self):
        FakeMetadata.verified.append(self.metadata_file)


@pytest.fixture
def library(monkeypatch, tmp_path, isolated_settings):
    json_root = tmp_path / "Json"
    locker_root = tmp_path / "Locker"
    metadata_root = tmp_path / "Metadata"
    hashes_root = tmp_path / "Hashes"
    for directory in [json_root, locker_root, metadata_root, hashes_root]:
        directory.mkdir()
    FakeGameInfo.games = {}
    FakeMetadata.verified = []
    state = {"json": json_root, "locker": locker_root, "metadata": metadata_root, "hashes": hashes_root,
             "previews": [], "confirm": True, "errors": []}
    tool_module = verify_game_files
    environment = tool_module.environment
    monkeypatch.setattr(tool_module.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(tool_module.logger, "setup_logging", lambda: None)
    monkeypatch.setattr(tool_module.prompts, "prompt_for_preview",
                        lambda operation, details: state["previews"].append(details) or state["confirm"])
    monkeypatch.setattr(tool_module.gameinfo, "GameInfo", FakeGameInfo)
    monkeypatch.setattr(tool_module.metadata, "Metadata", FakeMetadata)
    monkeypatch.setattr(tool_module.gameinfo, "derive_game_categories_from_file", lambda json_file: SWITCH)
    monkeypatch.setattr(tool_module.gameinfo, "find_json_game_names",
                        lambda supercategory, category, subcategory:
                        sorted(FakeGameInfo.games) if (supercategory, category, subcategory) == SWITCH else [])
    monkeypatch.setattr(environment, "get_game_json_metadata_root_dir", lambda: str(json_root))
    monkeypatch.setattr(environment, "get_game_json_metadata_file",
                        lambda supercategory, category, subcategory, name: str(json_root / (name + ".json")))
    monkeypatch.setattr(environment, "get_locker_gaming_root_dir", lambda: str(locker_root))
    monkeypatch.setattr(environment, "get_locker_gaming_files_dir",
                        lambda supercategory, category, subcategory, name: str(locker_root / subcategory.val() / name))
    monkeypatch.setattr(environment, "get_game_metadata_file",
                        lambda category, subcategory: str(metadata_root / (subcategory.val() + ".txt")))
    monkeypatch.setattr(environment, "get_game_hashes_metadata_file",
                        lambda supercategory, category, subcategory: str(hashes_root / (subcategory.val() + ".json")))
    monkeypatch.setattr(tool_module.hashing, "read_hash_file_json", lambda path: json.loads(open(path).read()))
    log_error = tool_module.logger.log_error

    def record_error(message, **kwargs):
        state["errors"].append(message)
        log_error(message, **kwargs)

    monkeypatch.setattr(tool_module.logger, "log_error", record_error)

    def add_game(name, data, stored = ()):
        FakeGameInfo.games[name] = data
        (json_root / (name + ".json")).write_text("{}")
        game_dir = locker_root / "Nintendo Switch" / name
        game_dir.mkdir(parents = True)
        for relative in stored:
            (game_dir / relative).write_text(relative)

    def run(*extra):
        monkeypatch.setattr(sys, "argv", ["verify_game_files", *extra])
        return system.run_main(tool_module.main)

    state["add_game"] = add_game
    state["run"] = run
    return state


def test_a_consistent_library_passes(library):
    library["add_game"]("Alpha", {"files": ["Alpha.nsp", "Alpha.xci"], "launch_file": "Alpha.xci"}, ["Alpha.nsp", "Alpha.xci"])
    library["add_game"]("Beta", {"files": ["Beta.iso"], "transform_file": "Beta.iso", "launch_file": "missing.xbe"}, ["Beta.iso"])
    library["add_game"]("Gamma", {})
    (library["metadata"] / "Nintendo Switch.txt").write_text("")
    (library["hashes"] / "Nintendo Switch.json").write_text(json.dumps({"Nintendo Switch/Alpha/Alpha.nsp": {}}))

    library["run"]("--no-preview")

    assert library["errors"] == []
    assert FakeMetadata.verified == [str(library["metadata"] / "Nintendo Switch.txt")]


def test_json_without_a_game_directory_quits(library):
    (library["json"] / "Orphan.json").write_text("{}")

    with pytest.raises(SystemExit) as raised:
        library["run"]("--no-preview")
    assert raised.value.code != 0
    assert library["errors"] == ["Extraneous json file '%s' found" % (library["json"] / "Orphan.json")]


def test_missing_launch_file_quits(library):
    library["add_game"]("Alpha", {"files": ["Alpha.nsp"], "launch_file": "Alpha.xci"}, ["Alpha.nsp"])

    with pytest.raises(SystemExit) as raised:
        library["run"]("--no-preview")
    assert raised.value.code != 0
    assert library["errors"] == ["File 'Alpha.xci' referenced in json file not found"]


def test_missing_transform_file_quits(library):
    library["add_game"]("Beta", {"transform_file": "Beta.iso", "launch_file": "default.xbe"}, ["default.xbe"])

    with pytest.raises(SystemExit) as raised:
        library["run"]("--no-preview")
    assert raised.value.code != 0
    assert library["errors"] == ["File 'Beta.iso' referenced in json file not found"]


def test_game_whose_json_disappeared_is_skipped(library, monkeypatch):
    library["add_game"]("Alpha", {"files": ["Alpha.nsp"]}, ["Alpha.nsp"])
    names = verify_game_files.gameinfo.find_json_game_names
    monkeypatch.setattr(verify_game_files.gameinfo, "find_json_game_names",
                        lambda *args: names(*args) + ["Ghost"] if names(*args) else [])

    library["run"]("--no-preview")

    assert library["errors"] == []


def test_hash_entry_without_a_file_quits(library):
    (library["hashes"] / "Nintendo Switch.json").write_text(json.dumps({"Nintendo Switch/Gone/Gone.nsp": {}}))

    with pytest.raises(SystemExit) as raised:
        library["run"]("--no-preview")
    assert raised.value.code != 0
    missing = library["locker"] / "Nintendo Switch" / "Gone" / "Gone.nsp"
    assert library["errors"] == ["File '%s' referenced in hash file not found" % missing]


def test_declined_preview_checks_nothing(library):
    (library["json"] / "Orphan.json").write_text("{}")
    library["confirm"] = False

    library["run"]()

    assert len(library["previews"]) == 1
    assert library["errors"] == []


def test_confirmed_preview_runs_the_checks(library):
    (library["json"] / "Orphan.json").write_text("{}")

    with pytest.raises(SystemExit):
        library["run"]()
    assert len(library["previews"]) == 1
    assert len(library["errors"]) == 1


def test_run_goes_through_the_shared_error_handling(library, monkeypatch):
    (library["json"] / "Orphan.json").write_text("{}")
    monkeypatch.setattr(sys, "argv", ["verify_game_files", "--no-preview"])

    with pytest.raises(SystemExit):
        verify_game_files.run()
    assert len(library["errors"]) == 1


def test_running_the_module_starts_the_command(monkeypatch):
    called = []
    monkeypatch.setattr(system, "run_main", lambda main: called.append(main))

    runpy.run_path(verify_game_files.__file__, run_name = "__main__")

    assert len(called) == 1
