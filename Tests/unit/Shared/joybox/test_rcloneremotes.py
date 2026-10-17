# Imports
import base64
import json

# Third-party imports
import pytest

# Local imports
from joybox import commandoptions, rcloneremotes


###########################################################
# Remotes from the settings
#
# A remote's options, credentials included, come from its locker's settings
# and reach rclone only as RCLONE_CONFIG_<NAME>_<OPTION> in the environment of
# a command that uses it: never in rclone.conf and never on a command line.
###########################################################

# What `rclone obscure` printed for PLAIN, so the codec stays rclone's
PLAIN = "joybox-test-password"
OBSCURED_BY_RCLONE = "G1c1cq92UG0JcqpkK1wr-P8_HY6m3MCGPoOSiiMEVe5BheoE"

HETZNER_CONFIG = {"host": "box.example", "user": "u1", "pass": PLAIN}
SERVICE_ACCOUNT = {"type": "service_account", "client_email": "locker@example.iam.gserviceaccount.com"}


@pytest.fixture
def lockers(isolated_settings):
    def define(locker, name, remote_type, remote_config = None, token = None):
        isolated_settings.set_value("UserData.Share", "locker_%s_name" % locker, name)
        isolated_settings.set_value("UserData.Share", "locker_%s_type" % locker, remote_type)
        isolated_settings.set_value("UserData.Share", "locker_%s_config" % locker,
            remote_config if isinstance(remote_config, str) or remote_config is None else json.dumps(remote_config))
        isolated_settings.set_value("UserData.Share", "locker_%s_token" % locker, token or "")
    return define


###########################################################
# Obscuring
###########################################################

def test_a_value_rclone_obscured_is_revealed():
    assert rcloneremotes.reveal_value(OBSCURED_BY_RCLONE) == PLAIN


def test_an_obscured_value_leads_with_its_iv_as_rclones_does():
    iv = bytes(range(16))
    obscured = rcloneremotes.obscure_value(PLAIN, iv)

    assert base64.urlsafe_b64decode(obscured + "=" * (-len(obscured) % 4))[:16] == iv
    assert rcloneremotes.reveal_value(obscured) == PLAIN


def test_each_obscuring_takes_a_fresh_iv():
    assert rcloneremotes.obscure_value(PLAIN) != rcloneremotes.obscure_value(PLAIN)


# abcde is a length base64 can't have, and the last decodes to bytes that
# are not text once unobscured
NOT_TEXT_ONCE_REVEALED = base64.urlsafe_b64encode(
    bytes(16) + rcloneremotes.apply_obscure_cipher(b"\xff\xfe", bytes(16))).decode("ascii").rstrip("=")


@pytest.mark.parametrize("value", ["hunter2", "has spaces", "", "QUJD", "not*base64", "abcde", NOT_TEXT_ONCE_REVEALED])
def test_a_plain_value_is_not_taken_for_an_obscured_one(value):
    assert rcloneremotes.reveal_value(value) is None


def test_ensuring_obscured_leaves_an_obscured_value_and_obscures_a_plain_one():
    assert rcloneremotes.ensure_obscured(OBSCURED_BY_RCLONE) == OBSCURED_BY_RCLONE
    assert rcloneremotes.reveal_value(rcloneremotes.ensure_obscured(PLAIN)) == PLAIN


###########################################################
# Remote options
###########################################################

def test_an_sftp_remote_takes_its_config_and_the_options_sftp_needs(lockers):
    lockers("hetzner", "HetznerBox", "SFTP", HETZNER_CONFIG)

    options = rcloneremotes.get_remote_options("HetznerBox")

    assert rcloneremotes.reveal_value(options.pop("pass")) == PLAIN
    assert options == {"type": "sftp", "host": "box.example", "user": "u1",
                       "shell_type": "unix", "disable_hashcheck": "true"}


def test_a_drive_remote_takes_its_service_account(lockers):
    lockers("gdrive", "GdriveBackup", "Drive", {"service_account_credentials": SERVICE_ACCOUNT, "root_folder_id": "abc"})

    options = rcloneremotes.get_remote_options("GdriveBackup")

    assert options == {"type": "drive", "scope": "drive", "root_folder_id": "abc",
                       "service_account_credentials": json.dumps(SERVICE_ACCOUNT)}


def test_a_remote_is_found_whatever_the_case_of_its_name(lockers):
    lockers("hetzner", "HetznerBox", "SFTP", {"host": "box.example"})

    assert rcloneremotes.get_remote_options("hetznerbox")["host"] == "box.example"


def test_an_obscured_password_is_passed_as_it_is(lockers):
    lockers("hetzner", "HetznerBox", "SFTP", dict(HETZNER_CONFIG, **{"pass": OBSCURED_BY_RCLONE}))

    assert rcloneremotes.get_remote_options("HetznerBox")["pass"] == OBSCURED_BY_RCLONE


def test_a_config_value_overrides_a_type_default_and_a_flag_becomes_rclones_spelling(lockers):
    lockers("hetzner", "HetznerBox", "SFTP", {"disable_hashcheck": False, "port": 23})

    options = rcloneremotes.get_remote_options("HetznerBox")

    assert (options["disable_hashcheck"], options["port"]) == ("false", "23")


def test_a_token_is_used_unless_the_config_has_one(lockers):
    lockers("hetzner", "HetznerBox", "WebDAV", None, token = "outer")
    assert rcloneremotes.get_remote_options("HetznerBox")["token"] == "outer"

    lockers("hetzner", "HetznerBox", "WebDAV", {"token": "inner"}, token = "outer")
    assert rcloneremotes.get_remote_options("HetznerBox")["token"] == "inner"


def test_a_name_no_locker_uses_has_no_options(lockers):
    lockers("hetzner", "HetznerBox", "SFTP")

    assert rcloneremotes.get_remote_options("Elsewhere") is None


def test_a_locker_without_a_type_has_no_options(lockers, caplog):
    lockers("hetzner", "HetznerBox", "")

    assert rcloneremotes.get_remote_options("HetznerBox") is None
    assert "has no type" in caplog.text


def test_a_config_that_is_not_an_object_is_refused(lockers, caplog):
    lockers("hetzner", "HetznerBox", "SFTP", '["host"]')

    assert rcloneremotes.get_remote_options("HetznerBox") is None
    assert "must be a JSON object" in caplog.text


###########################################################
# The environment
###########################################################

def test_each_named_remote_is_defined_for_rclone(lockers):
    lockers("hetzner", "HetznerBox", "SFTP", {"host": "box.example"})
    lockers("gdrive", "GdriveBackup", "Drive", {"root_folder_id": "abc"})

    environment = rcloneremotes.get_remote_environment(["HetznerBox", "GdriveBackup", "HetznerBox", None])

    assert environment["RCLONE_CONFIG_HETZNERBOX_HOST"] == "box.example"
    assert environment["RCLONE_CONFIG_GDRIVEBACKUP_ROOT_FOLDER_ID"] == "abc"
    assert (environment["RCLONE_CONFIG_HETZNERBOX_TYPE"], environment["RCLONE_CONFIG_GDRIVEBACKUP_TYPE"]) == ("sftp", "drive")


def test_only_the_remotes_a_command_names_are_resolved(lockers, monkeypatch):
    # A remote's credential may be a 1Password reference; one the command
    # doesn't use is never resolved
    lockers("hetzner", "HetznerBox", "SFTP", {"host": "box.example"})
    lockers("gdrive", "GdriveBackup", "Drive", {"root_folder_id": "abc"})
    read = []
    original = rcloneremotes.get_locker_setting
    monkeypatch.setattr(rcloneremotes, "get_locker_setting",
        lambda locker_type, field: read.append((str(locker_type), field)) or original(locker_type, field))

    rcloneremotes.get_remote_environment(["HetznerBox"])

    assert ("Gdrive", "config") not in read
    assert ("Hetzner", "config") in read


def test_a_remote_rclone_cannot_name_in_its_environment_is_refused(lockers, caplog):
    lockers("hetzner", "Hetzner-Box", "SFTP", {"host": "box.example"})

    assert rcloneremotes.get_remote_environment(["Hetzner-Box"]) == {}
    assert "letters, digits and _ only" in caplog.text


def test_rclone_options_add_the_remotes_to_the_callers_environment(lockers):
    lockers("hetzner", "HetznerBox", "SFTP", {"host": "box.example"})
    caller = commandoptions.CommandOptions(env = {"PATH": "/bin"}, include_stderr = True)

    options = rcloneremotes.get_rclone_options(["HetznerBox"], caller)

    assert options.get_env() == {"PATH": "/bin", "RCLONE_CONFIG_HETZNERBOX_TYPE": "sftp",
                                 "RCLONE_CONFIG_HETZNERBOX_HOST": "box.example",
                                 "RCLONE_CONFIG_HETZNERBOX_SHELL_TYPE": "unix",
                                 "RCLONE_CONFIG_HETZNERBOX_DISABLE_HASHCHECK": "true"}
    assert options.include_stderr() is True
    assert caller.get_env() == {"PATH": "/bin"}


def test_rclone_options_without_the_callers_start_from_this_process(lockers, monkeypatch):
    monkeypatch.setenv("JOYBOX_PROBE", "1")

    assert rcloneremotes.get_rclone_options([]).get_env()["JOYBOX_PROBE"] == "1"
