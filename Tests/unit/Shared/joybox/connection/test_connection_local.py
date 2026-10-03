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


def test_the_callers_options_are_left_alone():
    options = runoptions.RunOptions()

    connection_local.ConnectionLocal(runoptions.RunFlags(verbose = False), options)

    assert options.env == {}


def test_the_local_path_separator_is_the_platforms_own(connection):
    assert connection.get_path_separator() == os.sep


###########################################################
# Running commands
###########################################################

class FakeProcesses:
    # Stands in for the subprocess module; each call is recorded with the
    # options it was started with.
    PIPE = -1
    STDOUT = -2

    def __init__(self):
        self.calls = []
        self.output = b""
        self.code = 0
        self.error = None
        self.chunks = []

    def _start(self, cmd, kwargs):
        self.calls.append({"cmd": cmd, **kwargs})
        if self.error:
            raise self.error

    def run(self, cmd, **kwargs):
        self._start(cmd, kwargs)
        return type("Completed", (), {"stdout": self.output})()

    def call(self, cmd, **kwargs):
        self._start(cmd, kwargs)
        for name in ["stdout", "stderr"]:
            if hasattr(kwargs[name], "write"):
                kwargs[name].write("%s\n" % name)
        return self.code

    def Popen(self, cmd, **kwargs):
        self._start(cmd, kwargs)
        fake = self
        chunks = iter(self.chunks + [b""])

        class Process:
            stdout = type("Pipe", (), {"read": staticmethod(lambda size: next(chunks))})()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def wait(self):
                return fake.code
        return Process()


@pytest.fixture
def spawned(monkeypatch):
    fake = FakeProcesses()
    monkeypatch.setattr(connection_local, "subprocess", fake)
    return fake


@pytest.fixture
def logged(monkeypatch):
    lines = []
    monkeypatch.setattr(connection_local.logger, "log_info", lambda message, **kwargs: lines.append(message))
    monkeypatch.setattr(connection_local.logger, "log_error", lambda message, **kwargs: lines.append(str(message)))
    return lines


@pytest.fixture
def strict():
    return connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False, exit_on_failure = True),
        runoptions.RunOptions())


def test_the_home_directory_is_the_users(connection, monkeypatch):
    monkeypatch.setattr(connection_local.runtime, "get_home_directory", lambda: "/home/someone")

    assert connection.get_home_directory() == "/home/someone"


def test_output_is_decoded_and_trimmed(connection, spawned):
    spawned.output = b"  hello\n"

    assert connection.run_output(["echo", "hello"]) == "hello"


def test_standard_error_is_left_out_by_default(connection, spawned):
    connection.run_output(["echo"])

    assert "stderr" not in only(spawned.calls, None)


def test_standard_error_can_be_included(connection, spawned):
    connection.options.include_stderr = True

    connection.run_output(["echo"])

    assert only(spawned.calls, None)["stderr"] == FakeProcesses.STDOUT


def test_a_command_runs_with_the_connections_options(connection, spawned):
    connection.options.cwd = "/srv"
    connection.options.env = {"JOYBOX_TEST": "value"}

    connection.run_output(["pwd"])
    call = only(spawned.calls, None)

    assert (call["cwd"], call["env"], call["check"]) == ("/srv", {"JOYBOX_TEST": "value"}, False)


@pytest.mark.parametrize("method", ["run_output", "run_return_code", "run_blocking"])
def test_a_shell_command_is_run_as_one_string(connection, spawned, method):
    connection.options.shell = True

    getattr(connection, method)(["echo", "one two"])
    call = only(spawned.calls, None)

    assert call["cmd"] == "echo 'one two'"
    assert call["shell"] is True


def test_a_shell_string_reaches_the_shell_verbatim(connection, spawned):
    connection.options.shell = True

    connection.run_output("echo one | tr o 0; exit 4")

    assert only(spawned.calls, None)["cmd"] == "echo one | tr o 0; exit 4"


@pytest.mark.parametrize("method", ["run_output", "run_return_code", "run_blocking"])
def test_a_sudo_command_is_prefixed(connection, spawned, monkeypatch, method):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)

    getattr(connection, method)(["id"], sudo = True)

    assert only(spawned.calls, None)["cmd"] == ["sudo", "id"]


@pytest.mark.parametrize("method", ["run_output", "run_return_code", "run_blocking"])
def test_a_verbose_command_is_logged(connection, spawned, logged, method):
    connection.flags.verbose = True

    getattr(connection, method)(["echo", "hi"])

    assert logged == ['Running "echo hi"']


@pytest.mark.parametrize("method,failed", [
    ("run_output", ""), ("run_return_code", 1), ("run_blocking", 1)])
def test_a_command_that_cannot_start_reports_failure(connection, spawned, method, failed):
    spawned.error = FileNotFoundError("definitely-not-a-real-binary")

    assert getattr(connection, method)(["definitely-not-a-real-binary"]) == failed


@pytest.mark.parametrize("method", ["run_output", "run_return_code", "run_blocking"])
def test_a_command_that_cannot_start_can_quit_the_program(strict, spawned, logged, method):
    spawned.error = FileNotFoundError("definitely-not-a-real-binary")

    with pytest.raises(SystemExit):
        getattr(strict, method)(["definitely-not-a-real-binary"])
    assert logged == ["definitely-not-a-real-binary"]


def test_a_failing_command_reports_its_code(connection, spawned):
    spawned.code = 3

    assert connection.run_return_code(["false"]) == 3


def test_output_and_errors_can_be_redirected_to_files(connection, spawned, tmp_path):
    connection.options.stdout = str(tmp_path / "out.log")
    connection.options.stderr = str(tmp_path / "err.log")

    assert connection.run_return_code(["echo"]) == 0
    assert (tmp_path / "out.log").read_text() == "stdout\n"
    assert (tmp_path / "err.log").read_text() == "stderr\n"


def test_redirect_files_are_closed_when_the_command_cannot_start(connection, spawned, monkeypatch, tmp_path):
    connection.options.stdout = str(tmp_path / "out.log")
    opened = []
    real_open = open
    spawned.error = OSError("no exec")

    def tracking_open(*args, **kwargs):
        opened.append(real_open(*args, **kwargs))
        return opened[-1]

    monkeypatch.setattr(connection_local, "open", tracking_open, raising = False)

    assert connection.run_return_code(["echo"]) == 1
    assert opened[0].closed


def test_unredirected_output_is_inherited(connection, spawned):
    connection.run_return_code(["echo"])
    call = only(spawned.calls, None)

    assert (call["stdout"], call["stderr"]) == (None, None)


def test_blocking_output_is_streamed(connection, spawned, monkeypatch):
    streamed = []
    monkeypatch.setattr(connection_local.logger, "log_output", lambda text: None)
    monkeypatch.setattr(connection_local.logger, "record_output", streamed.append)
    spawned.chunks = [b"first\nsec", b"ond\n"]
    spawned.code = 4

    assert connection.run_blocking(["build"]) == 4
    assert streamed == ["first", "second"]


def test_pretending_runs_nothing(pretending, spawned):
    assert pretending.run_return_code(["sh", "-c", "exit 3"]) == 0
    assert pretending.run_output(["echo", "hello"]) == ""
    assert pretending.run_blocking(["echo", "hello"]) == 0
    assert spawned.calls == []


def test_a_checked_command_that_fails_quits_the_program(connection, monkeypatch):
    monkeypatch.setattr(connection, "run_blocking", lambda cmd, sudo = False: 1)

    with pytest.raises(SystemExit):
        connection.run_checked(["false"])


def test_a_checked_command_can_raise_instead(connection, monkeypatch):
    monkeypatch.setattr(connection, "run_blocking", lambda cmd, sudo = False: 1)

    with pytest.raises(ValueError):
        connection.run_checked(["false"], throw_exception = True)


def test_a_checked_command_that_succeeds_returns(connection, spawned):
    assert connection.run_checked(["true"]) is None


def test_an_interactive_command_blocks(connection, spawned):
    spawned.code = 4

    assert connection.run_interactive(["sh"]) == 4


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
    assert only(recorded)["cmd"] == ["/bin/mkdir", "-p", "/opt/app/data"]


def test_a_privileged_removal_takes_the_whole_tree(connection, recorded):
    # The separator keeps a path starting with a dash from being read as an
    # option, and the path is never parsed by a shell.
    connection.remove_file_or_directory("/opt/app", sudo = True)

    assert only(recorded)["cmd"] == ["/bin/rm", "-rf", "--", "/opt/app"]


def test_a_privileged_file_copy_is_not_recursive(connection, recorded, tmp_path):
    source = tmp_path / "file.txt"
    source.write_text("data")

    connection.copy_file_or_directory(str(source), "/opt/app/file.txt", sudo = True)

    assert only(recorded)["cmd"] == ["/bin/cp", str(source), "/opt/app/file.txt"]


def test_a_privileged_directory_copy_is_recursive(connection, recorded, tmp_path):
    source = tmp_path / "tree"
    source.mkdir()

    connection.copy_file_or_directory(str(source), "/opt/app", sudo = True)

    assert only(recorded)["cmd"] == ["/bin/cp", "-r", str(source), "/opt/app"]


def test_a_privileged_move_uses_mv(connection, recorded):
    connection.move_file_or_directory("/tmp/file", "/opt/app/file", sudo = True)

    assert only(recorded)["cmd"] == ["/bin/mv", "/tmp/file", "/opt/app/file"]


def test_a_privileged_link_is_forced_and_symbolic(connection, recorded):
    # Without -f an existing link is left pointing at the old target.
    connection.link_file_or_directory("/opt/app/current", "/usr/local/bin/app", sudo = True)

    assert only(recorded)["cmd"] == ["/bin/ln", "-sf", "/opt/app/current", "/usr/local/bin/app"]


def test_a_privileged_read_goes_through_cat(connection, recorded):
    connection.read_file("/etc/secret.conf", sudo = True)

    assert only(recorded)["cmd"] == ["cat", "/etc/secret.conf"]


def test_a_privileged_write_lands_at_the_destination(connection, recorded):
    # The file is written as the current user first and then copied into
    # place, because the destination directory is not writable.
    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is True

    call = only(recorded)
    assert call["cmd"][0] == "/bin/cp"
    assert call["cmd"][2] == "/etc/app.conf"
    assert call["sudo"] is True


def test_a_privileged_write_copies_rather_than_moves(connection, recorded):
    # A move would hand an existing file like /etc/hosts the staged file's
    # owner and 0600 mode; a copy keeps the destination's.
    connection.write_file("/etc/hosts", "contents", sudo = True)

    assert only(recorded)["cmd"][0] == "/bin/cp"


def test_a_privileged_write_puts_the_contents_in_the_staged_file(connection, monkeypatch):
    staged = []

    def run(cmd, sudo = False):
        with open(cmd[1]) as handle:
            staged.append(handle.read())
        return 0

    monkeypatch.setattr(connection, "run_return_code", run)
    connection.write_file("/etc/app.conf", "contents", sudo = True)

    assert staged == ["contents"]


def test_a_privileged_write_stages_a_world_readable_file(connection, monkeypatch):
    # cp gives a new destination the staged file's mode, and a system config
    # such as an xorg snippet has to be readable by more than root.
    modes = []

    def run(cmd, sudo = False):
        modes.append(os.stat(cmd[1]).st_mode & 0o777)
        return 0

    monkeypatch.setattr(connection, "run_return_code", run)
    connection.write_file("/etc/app.conf", "contents", sudo = True)

    assert modes == [0o644]


def test_a_privileged_write_cleans_up_the_staged_file(connection, recorded):
    connection.write_file("/etc/app.conf", "contents", sudo = True)

    assert not os.path.exists(only(recorded)["cmd"][1])


def test_a_failed_privileged_write_is_reported(connection, monkeypatch):
    monkeypatch.setattr(connection, "run_return_code", lambda cmd, sudo = False: 1)

    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is False


def test_a_privileged_extract_names_the_destination(connection, recorded):
    connection.extract_tar_archive("/tmp/app.tar.gz", "/opt/app", sudo = True)

    assert only(recorded)["cmd"] == ["/usr/bin/tar", "-xf", "/tmp/app.tar.gz", "-C", "/opt/app"]


def test_a_privileged_download_is_fetched_before_it_is_moved(connection, recorded, monkeypatch):
    downloaded = []
    monkeypatch.setattr(
        connection_local.network, "download_url",
        lambda url, output_file, **kwargs: downloaded.append((url, output_file)) or True)

    assert connection.download_file("https://example.test/app.tar", "/opt/app.tar", sudo = True) is True

    assert downloaded[0][0] == "https://example.test/app.tar"
    assert only(recorded)["cmd"] == ["/bin/mv", downloaded[0][1], "/opt/app.tar"]


def test_a_failed_privileged_download_is_not_moved(connection, recorded, monkeypatch):
    monkeypatch.setattr(
        connection_local.network, "download_url", lambda url, output_file, **kwargs: False)

    assert connection.download_file("https://example.test/app.tar", "/opt/app.tar", sudo = True) is False
    assert recorded == []


def test_a_privileged_transfer_merges_into_the_destination(connection, recorded, tmp_path):
    # "cp -r src dest" nests src inside an existing dest; copying src/. does not.
    source = tmp_path / "tree"
    source.mkdir()

    assert connection.transfer_files(str(source), "/opt/app", sudo = True) is True
    commands = [call["cmd"] for call in recorded]
    assert commands[0] == ["/bin/mkdir", "-p", "/opt/app"]
    assert commands[1][:2] == ["/bin/cp", "-r"]
    assert commands[1][2].endswith("/.")
    assert commands[1][3] == "/opt/app"
    assert all(call["sudo"] for call in recorded)


def test_a_privileged_transfer_honours_the_excludes(connection, monkeypatch, tmp_path):
    source = tmp_path / "tree"
    (source / ".git").mkdir(parents = True)
    (source / ".git" / "HEAD").write_text("ref")
    (source / "run.sh").write_text("#!/bin/sh")
    staged = []

    def run(cmd, sudo = False):
        if cmd[0] == "/bin/cp":
            staged.extend(sorted(os.listdir(cmd[2][:-2])))
        return 0

    monkeypatch.setattr(connection, "run_return_code", run)
    connection.transfer_files(str(source), "/opt/app", excludes = [".git"], sudo = True)

    assert staged == ["run.sh"]


def test_a_privileged_transfer_cleans_up_its_staging(connection, recorded, tmp_path):
    source = tmp_path / "tree"
    source.mkdir()
    connection.transfer_files(str(source), "/opt/app", sudo = True)

    assert not os.path.exists(recorded[1]["cmd"][2][:-2])


def test_a_privileged_file_transfer_is_a_plain_copy(connection, recorded, tmp_path):
    source = tmp_path / "app.conf"
    source.write_text("KEY=value")

    assert connection.transfer_files(str(source), "/etc/app.conf", sudo = True) is True
    assert only(recorded)["cmd"] == ["/bin/cp", str(source), "/etc/app.conf"]


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
    assert only(recorded)["cmd"] == ["/bin/chown", "-R", "app:app", "/opt/app"]


def test_permissions_are_changed_recursively(connection, recorded, monkeypatch):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)

    assert connection.change_permission("/opt/app", "750", sudo = True) is True
    assert only(recorded)["cmd"] == ["/bin/chmod", "-R", "750", "/opt/app"]


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


###########################################################
# Privileged failures and dry runs
###########################################################

SUDO_OPERATIONS = [
    ("make_directory", ("/opt/app",)),
    ("remove_file_or_directory", ("/opt/app",)),
    ("copy_file_or_directory", ("/tmp/a", "/opt/a")),
    ("move_file_or_directory", ("/tmp/a", "/opt/a")),
    ("link_file_or_directory", ("/tmp/a", "/opt/a")),
    ("extract_tar_archive", ("/tmp/a.tar", "/opt/a")),
    ("transfer_files", ("/tmp/a", "/opt/a")),
    ("write_file", ("/opt/a", "contents")),
    ("read_file", ("/opt/a",)),
    ("download_file", ("https://example.test/a", "/opt/a")),
    ("change_owner", ("/opt/a", "app:app")),
    ("change_permission", ("/opt/a", "750")),
]


@pytest.fixture
def on_linux(monkeypatch):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)


@pytest.mark.parametrize("method,args", SUDO_OPERATIONS)
def test_a_verbose_privileged_operation_is_logged(connection, recorded, logged, on_linux, monkeypatch, method, args):
    monkeypatch.setattr(connection_local.network, "download_url", lambda url, output_file, **kwargs: True)
    connection.flags.verbose = True

    getattr(connection, method)(*args, sudo = True)

    assert logged


@pytest.mark.parametrize("method,args", SUDO_OPERATIONS)
def test_pretending_runs_no_privileged_command(pretending, spawned, on_linux, method, args):
    result = getattr(pretending, method)(*args, sudo = True)

    assert result is (None if method == "read_file" else True)
    assert spawned.calls == []


@pytest.mark.parametrize("method,args", [op for op in SUDO_OPERATIONS if op[0] not in ("write_file", "read_file", "transfer_files")])
def test_a_failed_privileged_command_is_reported(connection, on_linux, monkeypatch, tmp_path, method, args):
    # A failure is the caller's to handle unless the connection exits on failure.
    monkeypatch.setattr(connection_local.network, "download_url", lambda url, output_file, **kwargs: True)
    monkeypatch.setattr(connection, "run_blocking", lambda cmd, sudo = False: 1)

    assert getattr(connection, method)(*args, sudo = True) is False


@pytest.mark.parametrize("method,args", [op for op in SUDO_OPERATIONS if op[0] not in ("read_file",)])
def test_a_failed_privileged_command_can_quit_the_program(strict, on_linux, logged, monkeypatch, method, args):
    monkeypatch.setattr(connection_local.network, "download_url", lambda url, output_file, **kwargs: True)
    monkeypatch.setattr(strict, "run_blocking", lambda cmd, sudo = False: 1)
    monkeypatch.setattr(strict, "run_return_code", lambda cmd, sudo = False: 1)
    monkeypatch.setattr(connection_local.os.path, "isdir", lambda path: False)

    with pytest.raises(SystemExit):
        getattr(strict, method)(*args, sudo = True)


@pytest.mark.parametrize("method,args", [("change_owner", ("/opt/a", "app:app")), ("change_permission", ("/opt/a", "750"))])
def test_an_unprivileged_ownership_change_runs_as_the_user(connection, recorded, on_linux, method, args):
    getattr(connection, method)(*args)

    assert only(recorded)["sudo"] is False


def test_a_privileged_write_that_cannot_stage_is_reported(connection, recorded, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError("no space")
    monkeypatch.setattr(connection_local.tempfile, "mkstemp", refuse)

    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is False
    assert recorded == []


def test_a_privileged_write_cleans_up_when_the_copy_cannot_start(connection, monkeypatch):
    staged = []

    def run(cmd, sudo = False):
        staged.append(cmd[1])
        raise OSError("no exec")

    monkeypatch.setattr(connection, "run_return_code", run)

    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is False
    assert not os.path.exists(staged[0])


def test_a_failed_privileged_download_leaves_no_staged_file(connection, recorded, monkeypatch):
    fetched = []
    monkeypatch.setattr(
        connection_local.network, "download_url",
        lambda url, output_file, **kwargs: fetched.append(output_file) and False)

    assert connection.download_file("https://example.test/a", "/opt/a", sudo = True) is False
    assert not os.path.exists(fetched[0])


def test_a_failed_privileged_move_leaves_no_staged_download(connection, monkeypatch):
    fetched = []
    monkeypatch.setattr(
        connection_local.network, "download_url",
        lambda url, output_file, **kwargs: fetched.append(output_file) or True)
    monkeypatch.setattr(connection, "run_blocking", lambda cmd, sudo = False: 1)

    assert connection.download_file("https://example.test/a", "/opt/a", sudo = True) is False
    assert not os.path.exists(fetched[0])


def test_a_privileged_download_is_moved_out_of_staging(connection, monkeypatch):
    moved = []

    def move(cmd, sudo = False, throw_exception = False):
        moved.append(cmd[1])
        os.remove(cmd[1])

    monkeypatch.setattr(connection_local.network, "download_url", lambda url, output_file, **kwargs: True)
    monkeypatch.setattr(connection, "run_checked", move)

    assert connection.download_file("https://example.test/a", "/opt/a", sudo = True) is True
    assert not os.path.exists(moved[0])


def test_a_failed_privileged_file_transfer_is_reported(connection, monkeypatch, tmp_path):
    source = tmp_path / "app.conf"
    source.write_text("KEY=value")
    monkeypatch.setattr(connection, "run_return_code", lambda cmd, sudo = False: 1)

    assert connection.transfer_files(str(source), "/etc/app.conf", sudo = True) is False


def test_a_privileged_transfer_that_cannot_stage_is_reported(connection, recorded, monkeypatch, tmp_path):
    monkeypatch.setattr(connection_local.fileops, "copy_file_or_directory", lambda *args, **kwargs: False)

    assert connection.transfer_files(str(tmp_path), "/opt/app", sudo = True) is False
    assert recorded == []


@pytest.mark.parametrize("failing", ["/bin/mkdir", "/bin/cp"])
def test_a_failed_privileged_transfer_step_is_reported(connection, monkeypatch, tmp_path, failing):
    ran = []

    def run(cmd, sudo = False):
        ran.append(cmd[0])
        return 1 if cmd[0] == failing else 0

    monkeypatch.setattr(connection, "run_return_code", run)

    assert connection.transfer_files(str(tmp_path), "/opt/app", sudo = True) is False
    assert ran[-1] == failing


def test_a_privileged_transfer_that_raises_is_reported(connection, monkeypatch, tmp_path):
    def refuse(*args, **kwargs):
        raise OSError("no space")
    monkeypatch.setattr(connection_local.tempfile, "mkdtemp", refuse)

    assert connection.transfer_files(str(tmp_path), "/opt/app", sudo = True) is False


def test_a_verbose_existence_check_is_logged(connection, logged, tmp_path):
    connection.flags.verbose = True

    connection.does_file_or_directory_exist(str(tmp_path))

    assert logged == ["Checking existence of %s" % tmp_path]


def test_an_existence_check_that_raises_is_reported(connection, monkeypatch):
    def refuse(path):
        raise OSError("denied")
    monkeypatch.setattr(connection_local.os.path, "exists", refuse)

    assert connection.does_file_or_directory_exist("/opt/app") is False


def test_a_file_is_read(connection, logged, tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("data")
    connection.flags.verbose = True

    assert connection.read_file(str(target)) == "data"
    assert logged == ["Reading file %s" % target]
