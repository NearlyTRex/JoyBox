# Imports
import configparser
import os

# Third-party imports
import pytest

# Local imports
from joybox.bootstrap import configsetup


###########################################################
# Creating and rebuilding JoyBox.ini
#
# A rebuilt file must keep every value the old one set, references included,
# so picking up new settings never costs a personal one.
###########################################################

def parse(path):
    parser = configparser.ConfigParser(interpolation = None)
    parser.read(path)
    return parser


@pytest.fixture
def answers(monkeypatch):
    # Answers to the questions, in the order they are asked; Enter takes the default
    queue = []

    def value(description, default_value = None):
        answer = queue.pop(0)
        return default_value if answer == "" else answer

    def choice(description, choices = (), default_value = None):
        answer = queue.pop(0)
        assert answer == "" or answer in choices
        return default_value if answer == "" else answer

    def confirmation(description, default_yes = False):
        answer = queue.pop(0)
        return default_yes if answer == "" else answer == "y"

    monkeypatch.setattr(configsetup.prompts, "prompt_for_value", value)
    monkeypatch.setattr(configsetup.prompts, "prompt_for_choice", choice)
    monkeypatch.setattr(configsetup.prompts, "prompt_for_confirmation", confirmation)
    return queue


###########################################################
# Questions
###########################################################

def test_a_host_streams_to_the_subnet_it_names(answers):
    answers.extend(["host", "10.0.0.0/24"])

    values = configsetup.ask_streaming_questions({})

    assert values["Tools.Sunshine"] == {"sunshine_streaming_host": "True", "sunshine_allowed_subnet": "10.0.0.0/24"}
    assert values["Tools.Moonlight"]["moonlight_autostart"] == "False"
    assert answers == []


def test_a_client_names_its_host_and_starts_at_login(answers):
    answers.extend(["client", "192.168.1.12", "", ""])

    values = configsetup.ask_streaming_questions({})

    assert values["Tools.Moonlight"] == {
        "moonlight_client": "True", "moonlight_host": "192.168.1.12", "moonlight_app": "Pegasus",
        "moonlight_autostart": "True"}
    assert values["Tools.Sunshine"]["sunshine_streaming_host"] == "False"


def test_a_client_takes_the_default_host_on_enter(answers):
    answers.extend(["client", "", "", ""])

    values = configsetup.ask_streaming_questions({})

    assert values["Tools.Moonlight"]["moonlight_host"] == "192.168.1.12"


def test_a_client_is_asked_again_until_it_names_a_host(answers):
    # A host cleared in the file leaves no default to take
    answers.extend(["client", "", "gamebox", "", "n"])

    values = configsetup.ask_streaming_questions({"Tools.Moonlight": {"moonlight_host": ""}})

    assert values["Tools.Moonlight"]["moonlight_host"] == "gamebox"
    assert values["Tools.Moonlight"]["moonlight_autostart"] == "False"


def test_none_turns_both_roles_off(answers):
    answers.append("none")

    values = configsetup.ask_streaming_questions({"Tools.Sunshine": {"sunshine_streaming_host": "True"}})

    assert values["Tools.Sunshine"]["sunshine_streaming_host"] == "False"
    assert values["Tools.Moonlight"]["moonlight_autostart"] == "False"


@pytest.mark.parametrize("values, role", [
    ({}, "none"),
    ({"Tools.Sunshine": {"sunshine_streaming_host": "True"}}, "host"),
    ({"Tools.Moonlight": {"moonlight_client": "True"}}, "client"),
    # A client that does not start at login is still a client
    ({"Tools.Moonlight": {"moonlight_client": "True", "moonlight_autostart": "False"}}, "client"),
    # Every file names a host, since it has a default, so that alone is no client
    ({"Tools.Moonlight": {"moonlight_host": "192.168.1.12"}}, "none"),
])
def test_the_current_role_is_the_default_answer(values, role):
    assert configsetup.get_streaming_role(values) == role


###########################################################
# A new file
###########################################################

def test_a_new_file_holds_the_answers(answers, tmp_path):
    answers.extend(["host", ""])
    path = str(tmp_path / "JoyBox.ini")

    assert configsetup.create_config(path, interactive = True)

    assert parse(path)["Tools.Sunshine"]["sunshine_streaming_host"] == "True"
    assert parse(path)["Tools.Sunshine"]["sunshine_allowed_subnet"] == "192.168.1.0/24"


def test_a_new_file_without_a_terminal_asks_nothing(answers, tmp_path):
    path = str(tmp_path / "JoyBox.ini")

    assert configsetup.create_config(path, interactive = False)

    assert parse(path)["Tools.Sunshine"]["sunshine_streaming_host"] == "False"


###########################################################
# Rebuilding
###########################################################

OLD_FILE = """[UserData.Share]
locker_gdrive_config =
locker_hetzner_config = op://Personal/JoyBox/UserData.Share/locker_hetzner_config

[Tools.Ollama]
ollama_ssh_host = testuser@192.168.1.15

[Custom.Section]
kept = yes
"""


@pytest.fixture
def old_file(tmp_path):
    path = tmp_path / "JoyBox.ini"
    path.write_text(OLD_FILE)
    return str(path)


def test_a_rebuild_keeps_every_value_the_old_file_set(old_file):
    assert configsetup.recreate_config(old_file, interactive = False)

    rebuilt = parse(old_file)
    assert rebuilt["Tools.Ollama"]["ollama_ssh_host"] == "testuser@192.168.1.15"
    assert rebuilt["UserData.Share"]["locker_hetzner_config"] == "op://Personal/JoyBox/UserData.Share/locker_hetzner_config"
    assert rebuilt["Custom.Section"]["kept"] == "yes"


def test_a_blank_value_stays_blank_rather_than_taking_the_default(old_file):
    # A default reference left blank on purpose, such as a remote not set up yet
    assert configsetup.recreate_config(old_file, interactive = False)

    assert parse(old_file)["UserData.Share"]["locker_gdrive_config"] == ""


def test_a_rebuild_adds_the_sections_the_old_file_lacked(old_file):
    assert configsetup.recreate_config(old_file, interactive = False)

    assert parse(old_file)["Tools.Moonlight"]["moonlight_app"] == "Pegasus"


def test_the_old_file_is_kept_readable_only_by_its_owner(old_file, tmp_path):
    assert configsetup.recreate_config(old_file, interactive = False)

    backups = [path for path in tmp_path.iterdir() if ".backup-" in path.name]
    assert len(backups) == 1
    assert backups[0].read_text() == OLD_FILE
    assert oct(os.stat(backups[0]).st_mode & 0o777) == "0o600"


def test_a_rebuild_asks_with_the_current_answers_as_defaults(old_file, answers):
    answers.extend(["client", "", "", ""])
    with open(old_file, "a", encoding = "utf-8") as handle:
        handle.write("\n[Tools.Moonlight]\nmoonlight_host = gamebox\n")

    assert configsetup.recreate_config(old_file, interactive = True)

    assert parse(old_file)["Tools.Moonlight"]["moonlight_host"] == "gamebox"


def test_an_unreadable_file_is_not_rebuilt(tmp_path):
    assert not configsetup.recreate_config(str(tmp_path / "absent.ini"), interactive = False)


def test_an_unparsable_file_is_not_rebuilt(tmp_path):
    path = tmp_path / "JoyBox.ini"
    path.write_text("no section header\n")

    assert not configsetup.recreate_config(str(path), interactive = False)
    assert path.read_text() == "no section header\n"


def test_a_failed_backup_leaves_the_old_file_alone(old_file, monkeypatch):
    monkeypatch.setattr(configsetup.fileops, "touch_file", lambda **kwargs: False)

    assert not configsetup.recreate_config(old_file, interactive = False)
    with open(old_file, encoding = "utf-8") as handle:
        assert handle.read() == OLD_FILE
