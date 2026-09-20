# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import runoptions
from joybox.connection import connection_local


###########################################################
# ConnectionLocal
#
# Every filesystem operation has two implementations: one that delegates to
# the shared fileops primitives, and one that shells out under sudo. The sudo
# path runs as root, so the command it builds is worth pinning exactly.
###########################################################

@pytest.fixture
def connection():
    return connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False, exit_on_failure = False),
        runoptions.RunOptions())


@pytest.fixture
def pretending():
    return connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False, exit_on_failure = False, pretend_run = True),
        runoptions.RunOptions())


@pytest.fixture
def recorded(connection, monkeypatch):
    # Stands in for every way this connection runs a command, so the sudo
    # branches can be driven without a root shell.
    calls = []

    def record(name):
        def run(cmd, sudo = False, **kwargs):
            calls.append({"name": name, "cmd": cmd, "sudo": sudo})
            return 0 if name != "run_output" else ""
        return run

    for name in ["run_output", "run_return_code", "run_blocking", "run_checked"]:
        monkeypatch.setattr(connection, name, record(name))
    return calls


@pytest.fixture
def delegated(monkeypatch):
    # Records what the non-sudo paths hand to the shared primitives.
    calls = []

    def record(module, name):
        def run(*args, **kwargs):
            calls.append({"name": name, "args": args, "kwargs": kwargs})
            return True
        monkeypatch.setattr(module, name, run)

    for name in ["copy_file_or_directory", "touch_file", "make_directory",
                 "remove_file_or_directory", "move_file_or_directory", "create_symlink"]:
        record(connection_local.fileops, name)
    record(connection_local.network, "download_url")
    record(connection_local.archive, "extract_archive")
    return calls


def only(calls, name = None):
    matching = [call for call in calls if name is None or call["name"] == name]
    assert len(matching) == 1, "expected one %s call, recorded %d" % (name or "command", len(matching))
    return matching[0]


###########################################################
# Environment
###########################################################

def test_the_process_environment_is_inherited():
    # A command started without an environment loses PATH, and every tool
    # lookup that follows fails.
    connection = connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False), runoptions.RunOptions())

    assert connection.options.env.get("PATH") == os.environ.get("PATH")


def test_an_explicit_environment_is_kept():
    options = runoptions.RunOptions()
    options.env = {"ONLY": "this"}

    connection = connection_local.ConnectionLocal(runoptions.RunFlags(verbose = False), options)

    assert connection.options.env == {"ONLY": "this"}


def test_the_local_path_separator_is_the_platforms_own(connection):
    assert connection.get_path_separator() == os.sep


###########################################################
# Running commands
###########################################################

def test_output_is_captured(connection):
    assert connection.run_output(["echo", "hello"]) == "hello"


def test_a_failing_command_reports_its_code(connection):
    assert connection.run_return_code(["sh", "-c", "exit 3"]) == 3


def test_a_command_that_does_not_exist_reports_failure(connection):
    assert connection.run_return_code(["definitely-not-a-real-binary"]) == 1


def test_output_of_a_command_that_does_not_exist_is_empty(connection):
    assert connection.run_output(["definitely-not-a-real-binary"]) == ""


def test_standard_error_is_left_out_by_default(connection):
    assert connection.run_output(["sh", "-c", "echo oops >&2; echo fine"]) == "fine"


def test_standard_error_can_be_included(connection):
    connection.options.include_stderr = True

    assert "oops" in connection.run_output(["sh", "-c", "echo oops >&2"])


def test_a_command_runs_in_the_directory_it_was_given(connection, tmp_path):
    connection.options.cwd = str(tmp_path)

    assert connection.run_output(["pwd"]) == str(tmp_path)


def test_a_command_sees_the_environment_it_was_given(connection):
    connection.options.env = {"JOYBOX_TEST": "value"}

    assert connection.run_output(["sh", "-c", "echo $JOYBOX_TEST"]) == "value"


def test_output_can_be_redirected_to_a_file(connection, tmp_path):
    target = tmp_path / "out.log"
    connection.options.stdout = str(target)

    assert connection.run_return_code(["echo", "written"]) == 0
    assert target.read_text().strip() == "written"


def test_errors_can_be_redirected_to_a_file(connection, tmp_path):
    target = tmp_path / "err.log"
    connection.options.stderr = str(target)

    connection.run_return_code(["sh", "-c", "echo oops >&2"])

    assert target.read_text().strip() == "oops"


def test_a_shell_command_is_run_through_a_shell(connection):
    connection.options.shell = True

    assert connection.run_output("echo one two") == "one two"


def test_pretending_runs_nothing(pretending):
    assert pretending.run_return_code(["sh", "-c", "exit 3"]) == 0
    assert pretending.run_output(["echo", "hello"]) == ""


def test_a_checked_command_that_fails_quits_the_program(connection):
    with pytest.raises(SystemExit):
        connection.run_checked(["sh", "-c", "exit 1"])


def test_a_checked_command_can_raise_instead(connection):
    with pytest.raises(ValueError):
        connection.run_checked(["sh", "-c", "exit 1"], throw_exception = True)


def test_a_checked_command_that_succeeds_returns(connection):
    assert connection.run_checked(["true"]) is None


def test_an_interactive_command_reports_its_code(connection):
    assert connection.run_interactive(["sh", "-c", "exit 4"]) == 4


###########################################################
# Privileged commands
###########################################################

def test_a_command_is_marked_for_sudo(connection, monkeypatch):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)

    assert connection.mark_command_as_sudo(["rm", "-rf", "/tmp/x"]) == ["sudo", "rm", "-rf", "/tmp/x"]


def test_sudo_is_not_used_off_linux(connection, monkeypatch):
    # There is no sudo on Windows, and prefixing it turns every command into
    # a command that does not exist.
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: False)

    assert connection.mark_command_as_sudo(["rm", "/tmp/x"]) == ["rm", "/tmp/x"]


def test_a_privileged_directory_is_made_with_its_parents(connection, recorded):
    assert connection.make_directory("/opt/app/data", sudo = True) is True
    assert only(recorded)["cmd"] == ["mkdir", "-p", "/opt/app/data"]


def test_a_privileged_removal_takes_the_whole_tree(connection, recorded):
    # The path is also protected from being read as an option by the
    # separator, so a path starting with a dash is still removed.
    connection.remove_file_or_directory("/opt/app", sudo = True)

    assert only(recorded)["cmd"] == ["sh", "-c", "rm -rf -- /opt/app"]


def test_a_privileged_file_copy_is_not_recursive(connection, recorded, tmp_path):
    source = tmp_path / "file.txt"
    source.write_text("data")

    connection.copy_file_or_directory(str(source), "/opt/app/file.txt", sudo = True)

    assert only(recorded)["cmd"] == ["cp", str(source), "/opt/app/file.txt"]


def test_a_privileged_directory_copy_is_recursive(connection, recorded, tmp_path):
    source = tmp_path / "tree"
    source.mkdir()

    connection.copy_file_or_directory(str(source), "/opt/app", sudo = True)

    assert only(recorded)["cmd"] == ["cp", "-r", str(source), "/opt/app"]


def test_a_privileged_move_uses_mv(connection, recorded):
    connection.move_file_or_directory("/tmp/file", "/opt/app/file", sudo = True)

    assert only(recorded)["cmd"] == ["mv", "/tmp/file", "/opt/app/file"]


def test_a_privileged_link_is_forced_and_symbolic(connection, recorded):
    # Without -f an existing link is left pointing at the old target.
    connection.link_file_or_directory("/opt/app/current", "/usr/local/bin/app", sudo = True)

    assert only(recorded)["cmd"] == ["ln", "-sf", "/opt/app/current", "/usr/local/bin/app"]


def test_a_privileged_read_goes_through_cat(connection, recorded):
    connection.read_file("/etc/secret.conf", sudo = True)

    assert only(recorded)["cmd"] == ["cat", "/etc/secret.conf"]


def test_a_privileged_write_lands_at_the_destination(connection, recorded):
    # The file is written as the current user first and then moved into place,
    # because the destination directory is not writable.
    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is True

    call = only(recorded)
    assert call["cmd"][0] == "mv"
    assert call["cmd"][2] == "/etc/app.conf"


def test_a_privileged_write_puts_the_contents_in_the_staged_file(connection, recorded):
    connection.write_file("/etc/app.conf", "contents", sudo = True)

    staged = only(recorded)["cmd"][1]
    with open(staged) as handle:
        assert handle.read() == "contents"
    os.remove(staged)


def test_a_privileged_extract_names_the_destination(connection, recorded):
    connection.extract_tar_archive("/tmp/app.tar.gz", "/opt/app", sudo = True)

    assert only(recorded)["cmd"] == ["tar", "-xf", "/tmp/app.tar.gz", "-C", "/opt/app"]


def test_a_privileged_download_is_fetched_before_it_is_moved(connection, recorded, monkeypatch):
    downloaded = []
    monkeypatch.setattr(
        connection_local.network, "download_url",
        lambda url, output_file, **kwargs: downloaded.append((url, output_file)) or True)

    assert connection.download_file("https://example.test/app.tar", "/opt/app.tar", sudo = True) is True

    assert downloaded[0][0] == "https://example.test/app.tar"
    assert only(recorded)["cmd"] == ["mv", downloaded[0][1], "/opt/app.tar"]


def test_a_failed_privileged_download_is_not_moved(connection, recorded, monkeypatch):
    monkeypatch.setattr(
        connection_local.network, "download_url", lambda url, output_file, **kwargs: False)

    assert connection.download_file("https://example.test/app.tar", "/opt/app.tar", sudo = True) is False
    assert recorded == []


def test_a_privileged_transfer_copies_the_tree(connection, recorded, tmp_path):
    source = tmp_path / "tree"
    source.mkdir()

    assert connection.transfer_files(str(source), "/opt/app", sudo = True) is True
    assert only(recorded)["cmd"] == ["cp", "-r", str(source), "/opt/app"]


def test_a_transfer_can_skip_an_existing_destination(connection, recorded, tmp_path):
    source = tmp_path / "tree"
    source.mkdir()
    dest = tmp_path / "existing"
    dest.mkdir()
    connection.flags.skip_existing = True

    assert connection.transfer_files(str(source), str(dest), sudo = True) is True
    assert recorded == []


def test_ownership_is_changed_recursively(connection, recorded, monkeypatch):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)

    assert connection.change_owner("/opt/app", "app:app", sudo = True) is True
    assert only(recorded)["cmd"] == ["chown", "-R", "app:app", "/opt/app"]


def test_permissions_are_changed_recursively(connection, recorded, monkeypatch):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)

    assert connection.change_permission("/opt/app", "750", sudo = True) is True
    assert only(recorded)["cmd"] == ["chmod", "-R", "750", "/opt/app"]


@pytest.mark.parametrize("method,args", [
    ("change_owner", ("/opt/app", "app:app")),
    ("change_permission", ("/opt/app", "750")),
])
def test_ownership_and_permissions_are_skipped_off_linux(connection, recorded, monkeypatch, method, args):
    # Windows has no equivalent, and failing there would block every install.
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: False)

    assert getattr(connection, method)(*args) is True
    assert recorded == []


###########################################################
# Delegating to the shared primitives
###########################################################

def test_an_unprivileged_directory_is_made_through_fileops(connection, delegated):
    connection.make_directory("/tmp/app")

    assert only(delegated, "make_directory")["args"] == ("/tmp/app",)


def test_an_unprivileged_write_is_a_touch(connection, delegated):
    connection.write_file("/tmp/app.conf", "contents")

    assert only(delegated, "touch_file")["kwargs"]["contents"] == "contents"


def test_an_unprivileged_link_is_a_symlink(connection, delegated):
    connection.link_file_or_directory("/tmp/target", "/tmp/link")

    assert only(delegated, "create_symlink")["args"] == ("/tmp/target", "/tmp/link")


def test_an_unprivileged_extract_goes_through_the_archiver(connection, delegated):
    connection.extract_tar_archive("/tmp/app.tar.gz", "/tmp/app")

    assert only(delegated, "extract_archive")["args"] == ("/tmp/app.tar.gz", "/tmp/app")


def test_an_unprivileged_download_goes_through_the_network(connection, delegated):
    connection.download_file("https://example.test/app.tar", "/tmp/app.tar")

    assert only(delegated, "download_url")["kwargs"]["output_file"] == "/tmp/app.tar"


def test_a_transfer_passes_its_excludes(connection, delegated):
    connection.transfer_files("/tmp/src", "/tmp/dest", excludes = ["*.log"])

    assert only(delegated, "copy_file_or_directory")["kwargs"]["excludes"] == ["*.log"]


@pytest.mark.parametrize("method,args,delegate", [
    ("make_directory", ("/tmp/app",), "make_directory"),
    ("remove_file_or_directory", ("/tmp/app",), "remove_file_or_directory"),
    ("move_file_or_directory", ("/tmp/a", "/tmp/b"), "move_file_or_directory"),
    ("copy_file_or_directory", ("/tmp/a", "/tmp/b"), "copy_file_or_directory"),
    ("write_file", ("/tmp/a", "contents"), "touch_file"),
])
def test_the_connections_flags_reach_the_primitive(connection, delegated, method, args, delegate):
    # A dry run that reaches fileops without pretend_run set writes for real.
    connection.flags.pretend_run = True
    connection.flags.verbose = True

    getattr(connection, method)(*args)
    passed = only(delegated, delegate)["kwargs"]

    assert passed["pretend_run"] is True
    assert passed["verbose"] is True
    assert passed["exit_on_failure"] is False


###########################################################
# Dry runs
###########################################################

def test_pretending_makes_no_temporary_directory(pretending):
    assert pretending.make_temporary_directory() is None


def test_a_temporary_directory_is_real(connection):
    from joybox import fileops

    temp_dir = connection.make_temporary_directory()

    assert os.path.isdir(temp_dir)
    fileops.remove_directory(temp_dir)


def test_a_failed_temporary_directory_is_reported(connection, monkeypatch):
    monkeypatch.setattr(
        connection_local.fileops, "create_temporary_directory",
        lambda **kwargs: (False, "no space"))

    assert connection.make_temporary_directory() is None


def test_pretending_assumes_paths_exist(pretending, tmp_path):
    # A dry run reports what a real run would do next, and a real run would
    # have created the path by then.
    assert pretending.does_file_or_directory_exist(str(tmp_path / "absent")) is True


def test_an_existing_path_is_found(connection, tmp_path):
    assert connection.does_file_or_directory_exist(str(tmp_path)) is True


def test_a_missing_path_is_not_found(connection, tmp_path):
    assert connection.does_file_or_directory_exist(str(tmp_path / "absent")) is False


def test_pretending_reads_nothing(pretending, tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("data")

    assert pretending.read_file(str(target)) is None


def test_reading_a_missing_file_yields_nothing(connection, tmp_path):
    assert connection.read_file(str(tmp_path / "absent.txt")) is None


def test_a_read_error_can_quit_the_program(tmp_path):
    strict = connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False, exit_on_failure = True),
        runoptions.RunOptions())

    with pytest.raises(SystemExit):
        strict.read_file(str(tmp_path / "absent.txt"))
