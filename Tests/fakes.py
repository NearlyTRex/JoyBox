# Imports
import os
import sys

# Local imports
from joybox import runoptions
from joybox.connection import connection
from joybox import cmdline

###########################################################
# Recording connection
#
# Installers never shell out directly - every side effect goes through
# self.connection, which is an abstract ~30-method interface. That makes the
# Connection the one seam worth faking: a recording double lets an installer be
# driven end to end and then asserted on, with nothing installed and no machine
# touched.
#
# Only the methods installers actually use are overridden. Anything else falls
# through to the base class, which is a no-op - so a test that starts exercising
# a new method will surface as a missing recording rather than a silent pass.
###########################################################

class RecordingConnection(connection.Connection):
    def __init__(
        self,
        flags = None,
        options = None,
        existing_paths = None,
        file_contents = None,
        return_codes = None,
        command_output = None):
        super().__init__(
            flags if flags is not None else runoptions.RunFlags(verbose = False),
            options if options is not None else runoptions.RunOptions())

        # What the test declares about the world
        self.existing_paths = set(existing_paths or [])
        self.file_contents = dict(file_contents or {})
        self.return_codes = dict(return_codes or {})
        self.command_output = dict(command_output or {})

        # What the installer did
        self.calls = []
        self.commands = []

        # Live contents, and an append-only history that removal does not clear
        self.written_files = {}
        self.write_log = []
        self.removed_paths = []
        self.made_directories = []
        self.permissions = []
        self.owners = []
        self.moved = []
        self.copied = []
        self.downloads = []
        self.crontab_added = []
        self.crontab_removed = []

    def copy(self):

        # Installer.__init__ does self.connection = connection.copy(), and the
        # base copy() is a deepcopy - so an installer would otherwise record
        # into a clone the test has no handle on. Returning self is the whole
        # point of the double: production keeps its isolated copy semantics,
        # and the recorder stays observable.
        return self

    ###########################################################
    # Recording
    ###########################################################

    def _record(self, method, *args, **kwargs):
        self.calls.append((method, args, kwargs))

    def _record_command(self, method, cmd, sudo):
        self._record(method, cmd, sudo = sudo)
        self.commands.append(cmd)
        return cmdline.create_command_string(cmd)

    def _lookup(self, table, cmd, default):
        command_string = cmdline.create_command_string(cmd)
        for fragment, value in table.items():
            if fragment in command_string:
                return value
        return default

    ###########################################################
    # Assertion helpers
    ###########################################################

    def command_strings(self):
        return [cmdline.create_command_string(cmd) for cmd in self.commands]

    def ran(self, *fragments):

        # True when a single command contains every fragment
        for command_string in self.command_strings():
            if all(fragment in command_string for fragment in fragments):
                return True
        return False

    def ran_any(self, *fragments):
        return any(self.ran(fragment) for fragment in fragments)

    def called(self, method):
        return [call for call in self.calls if call[0] == method]

    def written(self, path_fragment):

        # Contents of the first file written at a matching path, whether or not
        # it was cleaned up afterwards
        for path, contents in self.write_log:
            if path_fragment in path:
                return contents
        return None

    ###########################################################
    # Command execution
    ###########################################################

    def run_output(self, cmd, sudo = False):
        self._record_command("run_output", cmd, sudo)
        return self._lookup(self.command_output, cmd, "")

    def run_return_code(self, cmd, sudo = False):
        self._record_command("run_return_code", cmd, sudo)
        return self._lookup(self.return_codes, cmd, 0)

    def run_blocking(self, cmd, sudo = False):
        self._record_command("run_blocking", cmd, sudo)
        return self._lookup(self.return_codes, cmd, 0)

    def run_interactive(self, cmd, sudo = False):
        self._record_command("run_interactive", cmd, sudo)
        return self._lookup(self.return_codes, cmd, 0)

    def run_checked(self, cmd, sudo = False, throw_exception = False):
        self._record_command("run_checked", cmd, sudo)
        return self._lookup(self.return_codes, cmd, 0) == 0

    ###########################################################
    # Filesystem
    ###########################################################

    def make_temporary_directory(self):
        self._record("make_temporary_directory")
        return "/tmp/joybox-test"

    def make_directory(self, src, sudo = False):
        self._record("make_directory", src, sudo = sudo)
        self.made_directories.append(src)
        self.existing_paths.add(src)
        return True

    def remove_file_or_directory(self, src, sudo = False):
        self._record("remove_file_or_directory", src, sudo = sudo)
        self.removed_paths.append(src)
        self.existing_paths.discard(src)
        self.written_files.pop(src, None)
        return True

    def copy_file_or_directory(self, src, dest, sudo = False):
        self._record("copy_file_or_directory", src, dest, sudo = sudo)
        self.copied.append((src, dest))
        return True

    def move_file_or_directory(self, src, dest, sudo = False):
        self._record("move_file_or_directory", src, dest, sudo = sudo)
        self.moved.append((src, dest))
        if src in self.written_files:
            self.written_files[dest] = self.written_files.pop(src)
        self.existing_paths.discard(src)
        self.existing_paths.add(dest)
        return True

    def link_file_or_directory(self, src, dest, sudo = False):
        self._record("link_file_or_directory", src, dest, sudo = sudo)
        return True

    def does_file_or_directory_exist(self, src):
        self._record("does_file_or_directory_exist", src)
        return src in self.existing_paths

    def transfer_files(self, src, dest, excludes = [], sudo = False):
        self._record("transfer_files", src, dest, excludes = excludes, sudo = sudo)
        return True

    def read_file(self, src, sudo = False):
        self._record("read_file", src, sudo = sudo)
        if src in self.written_files:
            return self.written_files[src]
        return self.file_contents.get(src, "")

    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        self.written_files[src] = contents
        self.write_log.append((src, contents))
        self.existing_paths.add(src)
        return True

    def download_file(self, url, dest, sudo = False):
        self._record("download_file", url, dest, sudo = sudo)
        self.downloads.append((url, dest))
        self.existing_paths.add(dest)
        return True

    def extract_tar_archive(self, src, dest, sudo = False):
        self._record("extract_tar_archive", src, dest, sudo = sudo)
        return True

    def change_owner(self, src, owner, sudo = False):
        self._record("change_owner", src, owner, sudo = sudo)
        self.owners.append((src, owner))
        return True

    def change_permission(self, src, permission, sudo = False):
        self._record("change_permission", src, permission, sudo = sudo)
        self.permissions.append((src, permission))
        return True

    ###########################################################
    # Environment
    ###########################################################

    def set_current_working_directory(self, cwd):
        self._record("set_current_working_directory", cwd)
        return True

    def add_to_crontab(self, pattern):
        self._record("add_to_crontab", pattern)
        self.crontab_added.append(pattern)
        return True

    def remove_from_crontab(self, pattern):
        self._record("remove_from_crontab", pattern)
        self.crontab_removed.append(pattern)
        return True


###########################################################
# Recording installer
#
# Stands in for an installer inside Environment.process_components, which is
# pure orchestration - ordering, skip rules, failure handling - and needs no
# real installer to exercise.
###########################################################

class RecordingInstaller:
    def __init__(self, name, installed = False, results = None, call_log = None):
        self.name = name
        self.installed = installed

        # Per-action return values, e.g. {"install": False}
        self.results = dict(results or {})
        self.calls = []

        # Optional list shared between installers, so a test can assert the
        # order components ran in rather than only that each one ran.
        self.call_log = call_log

    def _record(self, action):
        self.calls.append(action)
        if self.call_log is not None:
            self.call_log.append((self.name, action))
        return self.results.get(action, True)

    def is_installed(self):
        return self.installed

    def get_package_status(self):
        return {"name": self.name, "installed": self.installed}

    def install(self):
        return self._record("install")

    def uninstall(self):
        return self._record("uninstall")

    def backup(self, tag = ""):
        return self._record("backup")

    def restore(self):
        return self._record("restore")


###########################################################
# Command recorder
#
# External tool wrappers build an argument list and hand it to joybox.command.
# Recording that list pins the whole invocation without running anything.
###########################################################

class RecordingCommand:

    def __init__(self, monkeypatch, returncode = 0, output = ""):
        from joybox import command

        self.calls = []
        self.returncode = returncode
        self.output = output

        def run_returncode_command(cmd, options = None, **kwargs):
            self.calls.append({"cmd": list(cmd), "options": options, "kwargs": kwargs})
            return self.returncode

        def run_output_command(cmd, options = None, **kwargs):
            self.calls.append({"cmd": list(cmd), "options": options, "kwargs": kwargs})
            return self.output

        def run_checked_command(cmd, options = None, **kwargs):
            self.calls.append({"cmd": list(cmd), "options": options, "kwargs": kwargs})
            return self.returncode == 0

        # Returns the pair some callers unpack rather than a bare value
        def run_command(cmd, options = None, **kwargs):
            self.calls.append({"cmd": list(cmd), "options": options, "kwargs": kwargs})
            return (self.output, self.returncode)

        for name, replacement in [
            ("run_returncode_command", run_returncode_command),
            ("run_output_command", run_output_command),
            ("run_checked_command", run_checked_command),
            ("run_command", run_command),
        ]:
            if hasattr(command, name):
                monkeypatch.setattr(command, name, replacement)

    # The single recorded command, failing loudly when there was not exactly one
    def only(self):
        assert len(self.calls) == 1, "expected one command, recorded %d" % len(self.calls)
        return self.calls[0]["cmd"]

    # The recorded command as one string, for substring checks
    def text(self, index = 0):
        return " ".join(str(part) for part in self.calls[index]["cmd"])

    # The value following a flag, so order changes are caught but position is not asserted
    def value_after(self, flag, index = 0):
        cmd = self.calls[index]["cmd"]
        position = cmd.index(flag)
        return cmd[position + 1]

    def options(self, index = 0):
        return self.calls[index]["options"]

    def ran(self):
        return len(self.calls) > 0
