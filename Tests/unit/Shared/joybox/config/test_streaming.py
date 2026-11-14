# Imports
import tomllib
from pathlib import Path

# Third-party imports
import pytest

# Local imports
from joybox.config import streaming

APPS = streaming.streaming_apps
APP_IDS = [app["name"] for app in APPS]
APP_FIELDS = {"name", "command", "detached", "undo", "image"}
STREAM_PLATFORMS = {"linux", "windows"}
PYPROJECT = Path(__file__).resolve().parents[5] / "pyproject.toml"


@pytest.fixture(scope = "module")
def console_scripts():
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["project"]["scripts"]


def test_app_names_are_unique():
    assert len(APP_IDS) == len(set(APP_IDS))


@pytest.mark.parametrize("app", APPS, ids = APP_IDS)
def test_app_uses_only_known_fields(app):
    assert "name" in app
    assert set(app) <= APP_FIELDS


@pytest.mark.parametrize("app", APPS, ids = APP_IDS)
def test_app_starts_one_way_at_most(app):
    assert not ("command" in app and "detached" in app)


@pytest.mark.parametrize("app", APPS, ids = APP_IDS)
def test_undo_only_accompanies_a_detached_start(app):
    assert ("undo" in app) <= ("detached" in app)


@pytest.mark.parametrize("app", [app for app in APPS if "detached" in app or "undo" in app],
    ids = [app["name"] for app in APPS if "detached" in app or "undo" in app])
def test_detached_and_undo_commands_cover_every_platform(app):
    assert all(set(app.get(field, {})) in (set(), STREAM_PLATFORMS) for field in ("detached", "undo"))
    assert all(command for field in ("detached", "undo") for command in app.get(field, {}).values())


@pytest.mark.parametrize("app", [app for app in APPS if "command" in app], ids = [app["name"] for app in APPS if "command" in app])
def test_command_is_a_joybox_console_script(app, console_scripts):
    assert app["command"] in console_scripts


@pytest.mark.parametrize("app", [app for app in APPS if "image" in app], ids = [app["name"] for app in APPS if "image" in app])
def test_image_is_a_bare_png_name(app):
    assert app["image"].endswith(".png")
    assert "/" not in app["image"]


def test_a_desktop_app_is_offered():
    assert [app["name"] for app in APPS if not {"command", "detached"} & set(app)] == ["Desktop"]
