# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.tools import pegasus


###########################################################
# Fakes
###########################################################

class Recorder:
    def __init__(self, results = None):
        self.calls = []
        self.results = list(results or [])

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.results.pop(0) if self.results else True


@pytest.fixture
def installed(monkeypatch):
    platforms = {"windows", "linux"}
    monkeypatch.setattr(pegasus.programs, "should_program_be_installed", lambda name, platform: platform in platforms)
    monkeypatch.setattr(pegasus.programs, "get_program_install_dir", lambda name, platform: "/install/%s" % platform)
    monkeypatch.setattr(pegasus.programs, "get_program_backup_dir", lambda name, platform: "/backup/%s" % platform)
    monkeypatch.setattr(pegasus.programs, "get_tool_config_value", lambda name, key: "dev")
    monkeypatch.setattr(pegasus.programs, "get_tool_path_config_value", lambda name, key, platform: "/themes/%s" % platform)
    return platforms


@pytest.fixture
def online(monkeypatch, installed):
    calls = []

    def recording(kind, recorder):
        def call(**kwargs):
            calls.append(kind)
            return recorder(**kwargs)
        return call

    fakes = {
        "github": Recorder(),
        "appimage": Recorder(),
        "theme": Recorder(),
    }
    monkeypatch.setattr(pegasus.release, "download_github_release", recording("github", fakes["github"]))
    monkeypatch.setattr(pegasus.release, "build_appimage_from_source", recording("appimage", fakes["appimage"]))
    monkeypatch.setattr(pegasus.network, "download_github_repository", recording("theme", fakes["theme"]))
    fakes["order"] = calls
    return fakes


###########################################################
# Config
###########################################################

def test_config_points_at_each_platform():
    tool = pegasus.Pegasus()

    assert tool.get_name() == "Pegasus"
    entry = tool.get_config()["Pegasus"]
    assert entry["program"]["linux"] == "Pegasus/linux/Pegasus.AppImage"
    assert entry["theme_github_branch"] == "dev"


###########################################################
# Setup
###########################################################

def test_setup_installs_program_and_theme_per_platform(online):
    assert pegasus.Pegasus().setup()

    assert online["order"] == ["github", "theme", "appimage", "theme"]
    assert online["github"].calls[0]["install_dir"] == "/install/windows"
    assert online["appimage"].calls[0]["install_dir"] == "/install/linux"
    assert [call["output_dir"] for call in online["theme"].calls] == [
        "/themes/windows/PegasusThemeGrid", "/themes/linux/PegasusThemeGrid"]
    assert {call["github_branch"] for call in online["theme"].calls} == {"dev"}


def test_setup_skips_platforms_not_installed(online, installed):
    installed.clear()

    assert pegasus.Pegasus().setup(config.SetupParams())
    assert online["order"] == []


@pytest.mark.parametrize("kind, results, expected", [
    ("github", [False], ["github"]),
    ("theme", [False], ["github", "theme"]),
    ("appimage", [False], ["github", "theme", "appimage"]),
    ("theme", [True, False], ["github", "theme", "appimage", "theme"]),
])
def test_setup_stops_at_the_first_failure(online, kind, results, expected):
    online[kind].results = results

    assert not pegasus.Pegasus().setup()
    assert online["order"] == expected


def test_setup_offline_installs_each_platform(monkeypatch, installed):
    stored = Recorder()
    monkeypatch.setattr(pegasus.release, "setup_stored_release", stored)

    assert pegasus.Pegasus().setup_offline()

    assert [call["archive_dir"] for call in stored.calls] == ["/backup/windows", "/backup/linux"]
    assert stored.calls[0]["search_file"] == "pegasus-fe.exe"


def test_setup_offline_windows_matches_the_online_install(monkeypatch, online):
    stored = Recorder()
    monkeypatch.setattr(pegasus.release, "setup_stored_release", stored)
    tool = pegasus.Pegasus()

    assert tool.setup()
    assert tool.setup_offline()

    # Offline installs only the files a fresh download would
    keys = ["search_file", "install_files"]
    expected = {key: online["github"].calls[0][key] for key in keys}
    assert {key: stored.calls[0][key] for key in keys} == expected


def test_setup_offline_skips_platforms_not_installed(monkeypatch, installed):
    installed.clear()
    stored = Recorder()
    monkeypatch.setattr(pegasus.release, "setup_stored_release", stored)

    assert pegasus.Pegasus().setup_offline(config.SetupParams())
    assert stored.calls == []


@pytest.mark.parametrize("results", [[False], [True, False]])
def test_setup_offline_stops_on_a_failed_install(monkeypatch, installed, results):
    stored = Recorder(results)
    monkeypatch.setattr(pegasus.release, "setup_stored_release", stored)

    assert not pegasus.Pegasus().setup_offline()
    assert len(stored.calls) == len(results)


###########################################################
# Configure
###########################################################

@pytest.fixture
def tools_root(monkeypatch, tmp_path):
    root = tmp_path / "tools"
    metadata = tmp_path / "metadata"
    monkeypatch.setattr(pegasus.environment, "get_tools_root_dir", lambda: str(root))
    monkeypatch.setattr(pegasus.environment, "get_game_pegasus_metadata_root_dir", lambda: str(metadata))
    monkeypatch.setattr(pegasus, "config_files", dict(pegasus.config_files))
    return root, metadata


def write(path, text = ""):
    path.parent.mkdir(parents = True, exist_ok = True)
    path.write_text(text)


def test_configure_lists_every_metadata_dir(tools_root):
    root, metadata = tools_root
    write(metadata / "Nintendo" / "metadata.pegasus.txt")
    write(metadata / "Sony" / "metadata.pegasus.txt")
    write(metadata / "Sony" / "notes.txt")

    assert pegasus.Pegasus().configure()

    expected = {str(metadata / "Nintendo"), str(metadata / "Sony")}
    for game_dirs in [
            root / "Pegasus/windows/config/game_dirs.txt",
            root / "Pegasus/linux/Pegasus.AppImage.home/.config/pegasus-frontend/game_dirs.txt"]:
        assert set(game_dirs.read_text().split("\n")) == expected
    settings_file = root / "Pegasus/windows/config/settings.txt"
    assert settings_file.read_text().startswith("general.theme: themes/PegasusThemeGrid/\n")
    assert (root / "Pegasus/windows/portable.txt").read_text() == ""


def test_configure_without_metadata_writes_empty_game_dirs(tools_root):
    root, metadata = tools_root

    assert pegasus.Pegasus().configure(config.SetupParams())

    assert (root / "Pegasus/windows/config/game_dirs.txt").read_text() == ""


def test_configure_stops_when_a_file_cannot_be_written(monkeypatch, tools_root):
    touched = Recorder([False])
    monkeypatch.setattr(pegasus.fileops, "touch_file", touched)

    assert not pegasus.Pegasus().configure()
    assert len(touched.calls) == 1
