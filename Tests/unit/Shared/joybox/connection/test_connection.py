# Imports
import pytest

# Local imports
from joybox import runoptions
from joybox.connection import connection as connection_module

Connection = connection_module.Connection


###########################################################
# Connection base
#
# The interface every installer runs through. The base class holds the parts
# that are the same locally and over ssh: sudo marking, crontab editing and
# path handling. A wrong answer here is applied to a real server.
###########################################################

class ScriptedConnection(Connection):
    # A base connection with the transport methods recorded rather than run.

    def __init__(self, output = "", **kwargs):
        super().__init__(**kwargs)
        self.output = output
        self.files = {}
        self.commands = []
        self.removed = []
        self.existing = set()

    def run_output(self, cmd, sudo = False):
        self.commands.append(("output", list(cmd)))
        return self.output

    def run_return_code(self, cmd, sudo = False):
        self.commands.append(("code", list(cmd)))
        return 0

    def run_checked(self, cmd, sudo = False, throw_exception = False):
        self.commands.append(("checked", list(cmd)))
        return True

    def write_file(self, src, contents, sudo = False):
        self.files[src] = contents
        return True

    def read_file(self, src, sudo = False):
        return self.files.get(src)

    def remove_file_or_directory(self, src, sudo = False):
        self.removed.append(src)
        return True

    def does_file_or_directory_exist(self, src):
        return src in self.existing


def crontab_of(conn):
    return conn.files.get("/tmp/crontab_update", "")


def quiet_logger(monkeypatch):
    recorded = []
    monkeypatch.setattr(connection_module.logger, "record_output", recorded.append)
    monkeypatch.setattr(connection_module.logger, "log_output", lambda text: None)
    return recorded


###########################################################
# Sudo marking
###########################################################

def test_a_list_command_is_prefixed_with_sudo():
    assert Connection().mark_command_as_sudo(["apt", "install"]) == ["sudo", "apt", "install"]


def test_a_string_command_is_prefixed_with_sudo():
    assert Connection().mark_command_as_sudo("apt install") == "sudo apt install"


def test_marking_does_not_change_the_original_list():
    # The caller reuses its command across hosts.
    cmd = ["apt", "install"]
    Connection().mark_command_as_sudo(cmd)

    assert cmd == ["apt", "install"]


def test_an_unsupported_command_is_returned_unchanged():
    assert Connection().mark_command_as_sudo(None) is None


def test_marking_twice_adds_sudo_twice():
    # Nothing deduplicates, so callers must not mark an already marked command.
    once = Connection().mark_command_as_sudo(["apt"])

    assert Connection().mark_command_as_sudo(once) == ["sudo", "sudo", "apt"]


###########################################################
# Copies
###########################################################

def test_a_copy_is_a_separate_object():
    original = Connection()

    assert original.copy() is not original


def test_a_copy_does_not_share_options():
    # Installers copy the connection and then set their own cwd.
    original = Connection()
    duplicate = original.copy()
    duplicate.set_current_working_directory("/elsewhere")

    assert original.get_options().cwd != "/elsewhere"


def test_a_copy_does_not_share_flags():
    original = Connection()
    duplicate = original.copy()
    duplicate.get_flags().pretend_run = True

    assert original.get_flags().pretend_run is False


def test_constructor_flags_are_copied():
    # A caller reuses one flag set across several connections.
    flags = runoptions.RunFlags()
    conn = Connection(flags = flags)
    conn.get_flags().pretend_run = True

    assert flags.pretend_run is False


###########################################################
# Options
###########################################################

def test_the_working_directory_is_set():
    conn = Connection()
    conn.set_current_working_directory("/srv/app")

    assert conn.get_options().cwd == "/srv/app"


def test_an_environment_variable_is_set():
    conn = Connection()
    conn.set_environment_var("DEBIAN_FRONTEND", "noninteractive")

    assert conn.get_options().env["DEBIAN_FRONTEND"] == "noninteractive"


def test_an_environment_variable_is_unset():
    conn = Connection()
    conn.set_environment_var("TOKEN", "secret")
    conn.unset_environment_var("TOKEN")

    assert "TOKEN" not in conn.get_options().env


def test_unsetting_a_missing_variable_raises():
    # Plain dict semantics; callers set before unsetting.
    with pytest.raises(KeyError):
        Connection().unset_environment_var("ABSENT")


def test_the_whole_environment_is_replaced():
    conn = Connection()
    conn.set_environment_var("OLD", "1")
    conn.set_environment({"NEW": "2"})

    assert conn.get_options().env == {"NEW": "2"}


def test_two_connections_do_not_share_an_environment():
    first = Connection()
    second = Connection()
    first.set_environment_var("TOKEN", "secret")

    assert "TOKEN" not in second.get_options().env


###########################################################
# Error handling
###########################################################

def test_an_error_returns_its_value_by_default():
    conn = Connection()
    conn.get_flags().exit_on_failure = False

    assert conn.handle_error("failed", Exception("boom")) is False


def test_an_error_can_return_a_chosen_value():
    conn = Connection()
    conn.get_flags().exit_on_failure = False

    assert conn.handle_error("failed", Exception("boom"), return_value = None) is None


def test_an_error_exits_when_asked(monkeypatch):
    conn = Connection()
    conn.get_flags().exit_on_failure = True
    quit_calls = []
    monkeypatch.setattr(connection_module.runtime, "quit_program",
                        lambda *args, **kwargs: quit_calls.append(True))
    conn.handle_error("failed", Exception("boom"))

    assert quit_calls == [True]


###########################################################
# Crontab
###########################################################

JOB = "0 4 * * * /usr/local/bin/backup.sh"


def test_a_job_is_added_to_an_empty_crontab():
    conn = ScriptedConnection(output = "")
    conn.add_to_crontab(JOB)

    assert crontab_of(conn).strip() == JOB


def test_a_job_is_appended_to_an_existing_crontab():
    conn = ScriptedConnection(output = "0 5 * * * /usr/local/bin/other.sh\n")
    conn.add_to_crontab(JOB)

    assert crontab_of(conn).strip().splitlines() == [
        "0 5 * * * /usr/local/bin/other.sh", JOB]


def test_adding_a_job_twice_does_not_duplicate_it():
    conn = ScriptedConnection(output = JOB + "\n")
    conn.add_to_crontab(JOB)

    assert conn.files == {}


def test_a_missing_crontab_message_is_not_treated_as_content():
    # crontab -l says "no crontab for <user>" for a fresh account.
    conn = ScriptedConnection(output = "no crontab for aryie\n")
    conn.add_to_crontab(JOB)

    assert crontab_of(conn).strip() == JOB


def test_an_installed_crontab_ends_with_a_newline():
    # cron rejects a file whose last line is unterminated.
    conn = ScriptedConnection(output = "")
    conn.add_to_crontab(JOB)

    assert crontab_of(conn).endswith("\n")


def test_the_temporary_crontab_is_removed():
    conn = ScriptedConnection(output = "")
    conn.add_to_crontab(JOB)

    assert conn.removed == ["/tmp/crontab_update"]


def test_the_crontab_is_installed_from_the_temporary_file():
    conn = ScriptedConnection(output = "")
    conn.add_to_crontab(JOB)

    assert ("checked", ["crontab", "/tmp/crontab_update"]) in conn.commands


def test_a_job_is_removed_from_the_crontab():
    conn = ScriptedConnection(output = "%s\n0 5 * * * other.sh\n" % JOB)
    conn.remove_from_crontab(JOB)

    assert crontab_of(conn).strip() == "0 5 * * * other.sh"


def test_removing_an_absent_job_changes_nothing():
    conn = ScriptedConnection(output = "0 5 * * * other.sh\n")

    assert conn.remove_from_crontab(JOB) is True
    assert conn.files == {}


def test_removing_from_an_empty_crontab_changes_nothing():
    conn = ScriptedConnection(output = "")

    assert conn.remove_from_crontab(JOB) is True
    assert conn.files == {}


def test_removing_the_only_job_leaves_an_empty_crontab():
    conn = ScriptedConnection(output = JOB + "\n")
    conn.remove_from_crontab(JOB)

    assert crontab_of(conn).strip() == ""


def test_a_job_is_matched_ignoring_surrounding_whitespace():
    conn = ScriptedConnection(output = "   %s   \n" % JOB)
    conn.remove_from_crontab(JOB)

    assert crontab_of(conn).strip() == ""


def test_adding_and_removing_returns_the_crontab_to_its_start():
    conn = ScriptedConnection(output = "0 5 * * * other.sh\n")
    conn.add_to_crontab(JOB)
    conn.output = crontab_of(conn)
    conn.remove_from_crontab(JOB)

    assert crontab_of(conn).strip() == "0 5 * * * other.sh"


def test_pretending_does_not_touch_the_crontab():
    conn = ScriptedConnection(output = "")
    conn.get_flags().pretend_run = True

    assert conn.add_to_crontab(JOB) is True
    assert conn.files == {}
    assert conn.commands == []


###########################################################
# Windows path
###########################################################

def setter_command(conn):
    return [cmd for kind, cmd in conn.commands if kind == "code"]


def test_a_path_is_appended_to_the_windows_path():
    conn = ScriptedConnection(output = "C:\\Windows;C:\\Tools")
    conn.add_to_windows_path("C:\\New")

    assert "C:\\Windows;C:\\Tools;C:\\New" in setter_command(conn)[0][-1]


def test_an_already_present_windows_path_is_not_added_again():
    conn = ScriptedConnection(output = "C:\\Windows;C:\\Tools")

    assert conn.add_to_windows_path("C:\\Tools") is True
    assert setter_command(conn) == []


def test_an_empty_windows_path_still_accepts_an_entry():
    conn = ScriptedConnection(output = "")
    conn.add_to_windows_path("C:\\New")

    assert "C:\\New" in setter_command(conn)[0][-1]


def test_an_unreadable_windows_path_still_accepts_an_entry():
    # A guard against a missing value is pointless if the next line reads it
    # unconditionally.
    conn = ScriptedConnection(output = None)

    assert conn.add_to_windows_path("C:\\New") is True
    assert setter_command(conn)


def test_blank_windows_path_entries_are_dropped():
    conn = ScriptedConnection(output = "C:\\Windows;;C:\\Tools;")
    conn.add_to_windows_path("C:\\New")

    assert ";;" not in setter_command(conn)[0][-1]


def test_pretending_does_not_change_the_windows_path():
    conn = ScriptedConnection(output = "C:\\Windows")
    conn.get_flags().pretend_run = True

    assert conn.add_to_windows_path("C:\\New") is True
    assert conn.commands == []


###########################################################
# Unix path
###########################################################

def test_a_path_is_exported_into_the_profile():
    conn = ScriptedConnection()
    conn.existing.add("~/.bashrc")
    conn.files["~/.bashrc"] = "# existing\n"
    conn.add_to_unix_path("/opt/tool/bin")

    assert 'export PATH="/opt/tool/bin:$PATH"' in conn.files["~/.bashrc"]


def test_the_existing_profile_content_is_kept():
    conn = ScriptedConnection()
    conn.existing.add("~/.bashrc")
    conn.files["~/.bashrc"] = "# existing\n"
    conn.add_to_unix_path("/opt/tool/bin")

    assert "# existing" in conn.files["~/.bashrc"]


def test_an_already_exported_path_is_not_added_again():
    conn = ScriptedConnection()
    conn.existing.add("~/.bashrc")
    conn.files["~/.bashrc"] = 'export PATH="/opt/tool/bin:$PATH"\n'
    conn.add_to_unix_path("/opt/tool/bin")

    assert conn.files["~/.bashrc"].count("/opt/tool/bin") == 1


def test_the_first_existing_profile_is_chosen():
    # The candidates are ordered by precedence at login.
    conn = ScriptedConnection()
    conn.existing.update(["~/.bashrc", "~/.zshrc"])
    conn.add_to_unix_path("/opt/tool/bin")

    assert "~/.bashrc" in conn.files
    assert "~/.zshrc" not in conn.files


def test_pretending_does_not_change_the_profile():
    conn = ScriptedConnection()
    conn.existing.add("~/.bashrc")
    conn.get_flags().pretend_run = True

    assert conn.add_to_unix_path("/opt/tool/bin") is True
    assert conn.files == {}


###########################################################
# Streaming output
###########################################################

def test_complete_lines_are_recorded(monkeypatch):
    recorded = quiet_logger(monkeypatch)
    Connection().stream_command_output([b"first\n", b"second\n"])

    assert recorded == ["first", "second"]


def test_a_line_split_across_chunks_is_joined(monkeypatch):
    # Output arrives in fixed size reads, not in lines.
    recorded = quiet_logger(monkeypatch)
    Connection().stream_command_output([b"par", b"tial", b" line\n"])

    assert recorded == ["partial line"]


def test_a_trailing_line_without_a_newline_is_recorded(monkeypatch):
    recorded = quiet_logger(monkeypatch)
    Connection().stream_command_output([b"no newline at the end"])

    assert recorded == ["no newline at the end"]


def test_carriage_returns_end_a_line(monkeypatch):
    # Progress meters overwrite with \r rather than \n.
    recorded = quiet_logger(monkeypatch)
    Connection().stream_command_output([b"10%\r20%\r30%\n"])

    assert recorded == ["10%", "20%", "30%"]


def test_blank_lines_are_not_recorded(monkeypatch):
    recorded = quiet_logger(monkeypatch)
    Connection().stream_command_output([b"\n\n   \nreal\n"])

    assert recorded == ["real"]


def test_a_multibyte_character_split_across_chunks_survives(monkeypatch):
    # A utf-8 character can straddle a read boundary.
    recorded = quiet_logger(monkeypatch)
    encoded = "\u30c9\u30e9\u30b4\u30f3".encode("utf-8")
    Connection().stream_command_output([encoded[:5], encoded[5:] + b"\n"])

    assert recorded == ["\u30c9\u30e9\u30b4\u30f3"]


def test_empty_chunks_are_skipped(monkeypatch):
    recorded = quiet_logger(monkeypatch)
    Connection().stream_command_output([b"", b"line\n", b""])

    assert recorded == ["line"]


def test_no_chunks_record_nothing(monkeypatch):
    recorded = quiet_logger(monkeypatch)
    Connection().stream_command_output([])

    assert recorded == []


###########################################################
# Home directory resolution
#
# A leading ~ is expanded by a shell, and neither transport goes through one:
# os.path.exists treats it as a directory named "~", and sftp resolves it the
# same way. Each side has to expand it against its own home.
###########################################################

class HomedConnection(ScriptedConnection):

    def __init__(self, home = "/home/deploy", separator = "/", **kwargs):
        super().__init__(**kwargs)
        self.home = home
        self.separator = separator

    def get_home_directory(self):
        return self.home

    def get_path_separator(self):
        return self.separator


def test_the_base_connection_knows_no_home():
    assert Connection().get_home_directory() is None


def test_the_base_connection_uses_posix_separators():
    # Remote hosts are posix; only the local transport follows the host.
    assert Connection().get_path_separator() == "/"


def test_a_home_path_is_expanded():
    conn = HomedConnection(home = "/home/deploy")

    assert conn.resolve_home_path("~/.bashrc") == "/home/deploy/.bashrc"


def test_a_bare_home_path_becomes_the_home():
    conn = HomedConnection(home = "/home/deploy")

    assert conn.resolve_home_path("~") == "/home/deploy"


def test_a_nested_home_path_is_expanded():
    conn = HomedConnection(home = "/home/deploy")

    assert conn.resolve_home_path("~/apps/jenkins/.env") == \
        "/home/deploy/apps/jenkins/.env"


def test_an_absolute_path_is_left_alone():
    conn = HomedConnection(home = "/home/deploy")

    assert conn.resolve_home_path("/etc/nginx/nginx.conf") == "/etc/nginx/nginx.conf"


def test_a_relative_path_is_left_alone():
    conn = HomedConnection(home = "/home/deploy")

    assert conn.resolve_home_path("apps/jenkins") == "apps/jenkins"


def test_another_users_home_is_left_alone():
    # ~deploy names a different account, which only a shell can resolve.
    conn = HomedConnection(home = "/home/deploy")

    assert conn.resolve_home_path("~other/.bashrc") == "~other/.bashrc"


def test_a_path_is_left_alone_when_the_home_is_unknown():
    # Better an unexpanded path than one built against the wrong home.
    conn = ScriptedConnection()

    assert conn.resolve_home_path("~/.bashrc") == "~/.bashrc"


def test_a_trailing_separator_on_the_home_is_not_doubled():
    conn = HomedConnection(home = "/home/deploy/")

    assert conn.resolve_home_path("~/.bashrc") == "/home/deploy/.bashrc"


def test_windows_separators_are_used_when_that_is_the_side():
    conn = HomedConnection(home = "C:\\Users\\aryie", separator = "\\")

    assert conn.resolve_home_path("~/Tools/bin") == "C:\\Users\\aryie\\Tools\\bin"


def test_a_windows_home_path_is_expanded():
    conn = HomedConnection(home = "C:\\Users\\aryie", separator = "\\")

    assert conn.resolve_home_path("~\\Tools") == "C:\\Users\\aryie\\Tools"


@pytest.mark.parametrize("value", [None, 12345, ["~/x"], b"~/x"])
def test_a_non_string_path_is_returned_unchanged(value):
    conn = HomedConnection()

    assert conn.resolve_home_path(value) is value


def test_expanding_twice_changes_nothing():
    conn = HomedConnection(home = "/home/deploy")
    once = conn.resolve_home_path("~/.bashrc")

    assert conn.resolve_home_path(once) == once


###########################################################
# Profiles are probed by resolved path
###########################################################

def test_a_profile_is_probed_by_its_resolved_path():
    # Probing "~/.bashrc" reports missing even when the file is there, so every
    # candidate fails and the export lands on a literal ~ path.
    conn = HomedConnection(home = "/home/deploy")
    conn.existing.add("/home/deploy/.bashrc")
    conn.files["/home/deploy/.bashrc"] = "# existing\n"
    conn.add_to_unix_path("/opt/tool/bin")

    assert 'export PATH="/opt/tool/bin:$PATH"' in conn.files["/home/deploy/.bashrc"]


def test_no_literal_tilde_path_is_written():
    conn = HomedConnection(home = "/home/deploy")
    conn.existing.add("/home/deploy/.bashrc")
    conn.add_to_unix_path("/opt/tool/bin")

    assert not any(path.startswith("~") for path in conn.files)


def test_the_fallback_profile_is_also_resolved():
    # With no candidate present the first one is used, and it must not be the
    # unexpanded path.
    conn = HomedConnection(home = "/home/deploy")
    conn.add_to_unix_path("/opt/tool/bin")

    assert list(conn.files) == ["/home/deploy/.bash_profile"]


def test_an_unknown_home_still_falls_back_to_a_candidate():
    conn = ScriptedConnection()
    conn.add_to_unix_path("/opt/tool/bin")

    assert list(conn.files) == ["~/.bash_profile"]
