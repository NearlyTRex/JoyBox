# Third-party imports
import pytest

# Local imports
from joybox import config, sync
from sync_helpers import REMOTE, REMOTE_TYPE, REMOTE_PATH, record


###########################################################
# Queries that answer from rclone's exit code
#
# rclone writes its errors to stderr, which a plain capture never sees. A
# question answered from stdout alone reads a failed listing as an empty one,
# so these tests drive the exit code with clean output.
###########################################################

MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def test_rclone_is_reported_as_installed_when_the_tool_is(monkeypatch):
    monkeypatch.setattr(sync.programs, "is_tool_installed", lambda name: name == "RClone")

    assert sync.is_tool_installed() is True


def test_a_query_decodes_byte_output(monkeypatch):
    monkeypatch.setattr(sync.command, "run_command", lambda **kwargs: (b"text", 0))

    assert sync.run_query_command(["rclone"]) == ("text", 0)


def test_a_query_with_no_output_reads_as_empty_text(monkeypatch):
    monkeypatch.setattr(sync.command, "run_command", lambda **kwargs: (None, 3))

    assert sync.run_query_command(["rclone"]) == ("", 3)


def test_a_query_passes_its_run_flags_on(monkeypatch):
    recorder = record(monkeypatch)
    sync.run_query_command(
        ["rclone"], verbose = True, pretend_run = True, exit_on_failure = True)
    kwargs = recorder.calls[0]["kwargs"]

    assert kwargs["verbose"] is True
    assert kwargs["pretend_run"] is True
    assert kwargs["exit_on_failure"] is True
    assert kwargs["capture_output"] is True


###########################################################
# Configured remotes
###########################################################

def test_a_failed_remote_listing_lists_nothing(rclone, quiet, monkeypatch):
    record(monkeypatch, returncode = 1, output = "hetzner:\n")

    assert sync.get_configured_remotes() == []


def test_blank_lines_are_not_remotes(rclone, monkeypatch):
    record(monkeypatch, output = "hetzner:\n\n  \ngdrive:\n")

    assert sync.get_configured_remotes() == ["hetzner:", "gdrive:"]


def test_the_remote_check_passes_its_flags_to_the_listing(rclone, quiet, monkeypatch):
    seen = []
    monkeypatch.setattr(
        sync, "get_configured_remotes", lambda **kwargs: seen.append(kwargs) or [])
    sync.is_remote_configured(
        REMOTE, REMOTE_TYPE, verbose = True, pretend_run = True, exit_on_failure = True)

    assert seen == [{"verbose": True, "pretend_run": True, "exit_on_failure": True}]


def test_a_remote_whose_name_only_starts_the_same_is_not_configured(rclone, quiet, monkeypatch):
    # hetznerEnc being set up says nothing about hetzner itself.
    monkeypatch.setattr(sync, "get_configured_remotes", lambda **kwargs: ["hetznerEnc:"])
    recorder = record(monkeypatch, output = "type = %s\n" % sync.get_remote_raw_type(REMOTE_TYPE))

    assert sync.is_remote_configured(REMOTE, REMOTE_TYPE) is False
    assert recorder.ran() is False


def test_a_remote_whose_config_cannot_be_shown_is_not_configured(rclone, quiet, monkeypatch):
    monkeypatch.setattr(sync, "get_configured_remotes", lambda **kwargs: ["hetzner:"])
    record(monkeypatch, returncode = 1, output = "")

    assert sync.is_remote_configured(REMOTE, REMOTE_TYPE) is False


def test_a_config_without_a_type_line_is_plainly_false(rclone, quiet, monkeypatch):
    monkeypatch.setattr(sync, "get_configured_remotes", lambda **kwargs: ["hetzner:"])
    record(monkeypatch, output = "[hetzner]\nhost = example.test\n")

    assert sync.is_remote_configured(REMOTE, REMOTE_TYPE) is False


def test_a_configured_remote_check_without_rclone_is_false(no_rclone, quiet, monkeypatch):
    monkeypatch.setattr(sync, "get_configured_remotes", lambda **kwargs: ["hetzner:"])

    assert sync.is_remote_configured(REMOTE, REMOTE_TYPE) is False


###########################################################
# Setting up remotes
###########################################################

def test_a_token_is_handed_to_a_manual_remote(rclone, recording_command):
    sync.setup_manual_remote(REMOTE, REMOTE_TYPE, remote_token = '{"access_token": "x"}')

    assert 'token={"access_token": "x"}' in recording_command.only()


def test_a_token_in_the_config_is_not_doubled(rclone, recording_command):
    sync.setup_manual_remote(
        REMOTE, REMOTE_TYPE, remote_token = "outer", remote_config = {"token": "inner"})
    cmd = recording_command.only()

    assert "token=inner" in cmd
    assert "token=outer" not in cmd


def test_a_config_that_is_not_an_object_is_refused(rclone, quiet, recording_command):
    assert sync.setup_remote(REMOTE, config.RemoteType.SFTP, remote_config = '["host"]') is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("call", ["setup_manual_remote", "setup_autoconnect_remote"])
def test_a_verbose_setup_asks_rclone_to_be_verbose(rclone, recording_command, call):
    getattr(sync, call)(REMOTE, config.RemoteType.DRIVE, verbose = True)

    assert all("--verbose" in entry["cmd"] for entry in recording_command.calls)


def test_a_failed_authorization_reports_failure(rclone, monkeypatch):
    codes = iter([0, 1])
    monkeypatch.setattr(
        sync.command, "run_returncode_command", lambda **kwargs: next(codes))

    assert sync.setup_autoconnect_remote(REMOTE, config.RemoteType.DRIVE) is False


###########################################################
# Checksums and modification times
###########################################################

def test_a_failed_checksum_query_yields_nothing(rclone, monkeypatch):
    record(monkeypatch, returncode = 3, output = "%s  Game.zip\n" % MD5)

    assert sync.get_path_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None


def test_a_file_named_error_still_has_a_checksum(rclone, monkeypatch):
    record(monkeypatch, output = "%s  error_log.txt\n" % MD5)

    assert sync.get_path_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH) == MD5


def test_a_blank_checksum_is_not_read_as_the_filename(rclone, monkeypatch):
    # Backends without md5 print spaces where the hash would be.
    record(monkeypatch, output = "%s  Game.zip\n" % (" " * 32))

    assert sync.get_path_md5(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None


def test_a_failed_time_query_is_nothing(rclone, monkeypatch):
    record(monkeypatch, returncode = 3, output = "  1024 2024-01-02 03:04:05.000000000 Game.zip\n")

    assert sync.get_path_mod_time(REMOTE, REMOTE_TYPE, REMOTE_PATH) == 0


def test_a_file_named_error_still_has_a_time(rclone, monkeypatch):
    record(monkeypatch, output = "  1024 2024-01-02 03:04:05.000000000 not found error.txt\n")

    assert sync.get_path_mod_time(REMOTE, REMOTE_TYPE, REMOTE_PATH) > 0


def test_byte_output_is_decoded_for_a_time(rclone, monkeypatch):
    record(monkeypatch, output = b"  1024 2024-01-02 03:04:05.000000000 Game.zip\n")

    assert sync.get_path_mod_time(REMOTE, REMOTE_TYPE, REMOTE_PATH) > 0


###########################################################
# Existence and contents
###########################################################

def test_a_failed_directory_listing_means_it_does_not_exist(rclone, monkeypatch):
    # The not-found message goes to stderr, so stdout is empty.
    record(monkeypatch, returncode = 3, output = "")

    assert sync.does_directory_exist(REMOTE, REMOTE_TYPE, "/Gaming") is False


def test_byte_output_is_decoded_for_a_directory_check(rclone, monkeypatch):
    record(monkeypatch, output = b"directory not found")

    assert sync.does_directory_exist(REMOTE, REMOTE_TYPE, "/Gaming") is False


def test_a_file_check_without_rclone_is_false(no_rclone, quiet, recording_command):
    assert sync.does_file_exist(REMOTE, REMOTE_TYPE, "/Gaming/game.zip") is False
    assert recording_command.ran() is False


def test_a_path_with_files_contains_files(rclone, recording_command, monkeypatch):
    recorder = record(monkeypatch, output = "game.zip\n")

    assert sync.does_path_contain_files(REMOTE, REMOTE_TYPE, REMOTE_PATH) is True
    assert recorder.only()[1:3] == ["lsf", "--files-only"]


@pytest.mark.parametrize("output", ["", "   \n"])
def test_a_path_without_files_contains_none(rclone, monkeypatch, output):
    record(monkeypatch, output = output)

    assert sync.does_path_contain_files(REMOTE, REMOTE_TYPE, REMOTE_PATH) is False


def test_a_failed_contents_listing_contains_no_files(rclone, monkeypatch):
    record(monkeypatch, returncode = 3, output = "partial.zip\n")

    assert sync.does_path_contain_files(REMOTE, REMOTE_TYPE, REMOTE_PATH) is False


def test_byte_output_is_decoded_for_a_contents_check(rclone, monkeypatch):
    record(monkeypatch, output = b"game.zip\n")

    assert sync.does_path_contain_files(REMOTE, REMOTE_TYPE, REMOTE_PATH) is True


def test_a_contents_check_without_rclone_is_false(no_rclone, quiet, recording_command):
    assert sync.does_path_contain_files(REMOTE, REMOTE_TYPE, REMOTE_PATH) is False
    assert recording_command.ran() is False


###########################################################
# Creating directories
###########################################################

def test_a_directory_that_already_exists_counts_as_created(rclone, monkeypatch):
    recorder = record(monkeypatch, returncode = 1, output = "ERROR : Directory already exists")

    assert sync.create_remote_directory(REMOTE, REMOTE_TYPE, "/Gaming/New") is True
    assert len(recorder.calls) == 1


def test_a_directory_creation_captures_stderr(rclone, recording_command):
    sync.create_remote_directory(REMOTE, REMOTE_TYPE, "/Gaming/New")

    assert recording_command.options().include_stderr() is True


def test_a_verbose_directory_creation_is_verbose(rclone, recording_command):
    sync.create_remote_directory(REMOTE, REMOTE_TYPE, "/Gaming/New", verbose = True)

    assert "--verbose" in recording_command.only()
