# Imports
import os
import sys

# Third-party imports
import pytest

###########################################################
# Path wiring
#
# Both trees are consumed off disk via sys.path rather than installed, exactly
# as Scripts/bin/*.py and bootstrap.py do it. Tests have to wire the same paths
# or nothing imports.
###########################################################

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
SHARED_DIR = os.path.join(REPO_ROOT, "Shared")
BOOTSTRAP_DIR = os.path.join(REPO_ROOT, "Bootstrap")
INSTALLERS_DIR = os.path.join(SHARED_DIR, "joybox", "bootstrap", "installers")
SCRIPTS_BIN_DIR = os.path.join(REPO_ROOT, "Scripts", "bin")

for _path in (TESTS_DIR, SHARED_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

###########################################################
# The seal
#
# Applied when the session starts, before any test module is imported, so it
# covers collection as well as the tests: a module that builds something at
# import time reads settings and may start programs before any fixture runs.
# From here on HOME is a scratch directory, the settings file is a generated
# default with no secret references, and the programs below are refused.
###########################################################

# Programs a test must never start for real: they raise privileges, read the
# password manager, reach another machine, or change this one's services and VMs
SEALED_PROGRAMS = {
    "sudo", "su", "pkexec", "doas",
    "op",
    "ssh", "scp", "sftp", "sshfs", "ssh-copy-id", "sshpass",
    "virsh", "virt-install", "qemu-system-x86_64",
    "systemctl", "apt", "apt-get", "ufw", "iptables", "mkcert",
    "useradd", "usermod", "groupadd", "adduser",
}

_unsealed = {}


def get_program_name(args, shell = False):
    import shlex
    if isinstance(args, (str, bytes)):
        text = args.decode() if isinstance(args, bytes) else args
        tokens = shlex.split(text) if text.strip() else []
    else:
        tokens = [str(arg) for arg in args]
    for token in tokens:
        # Leading VAR=value assignments in a shell string are not the program
        if shell and "=" in token and not token.startswith(("/", ".")):
            continue
        return os.path.basename(token)
    return ""


def check_sealed(args, shell = False):
    program = get_program_name(args, shell = shell)
    if program in SEALED_PROGRAMS:
        raise RuntimeError(
            "tests may not run %s for real; replace the connection or "
            "command runner with a fake" % program)


def seal_programs():
    import subprocess

    class SealedPopen(subprocess.Popen):
        def __init__(self, args, *rest, **kwargs):
            check_sealed(args, shell = kwargs.get("shell", False))
            super().__init__(args, *rest, **kwargs)

    _unsealed["Popen"] = subprocess.Popen
    _unsealed["system"] = os.system
    subprocess.Popen = SealedPopen

    def sealed_system(command):
        check_sealed(command, shell = True)
        return _unsealed["system"](command)
    os.system = sealed_system

    for name in ["execv", "execve", "execvp", "execvpe", "execl", "execlp"]:
        original = getattr(os, name)
        _unsealed[name] = original
        def sealed_exec(path, *rest, original = original):
            check_sealed([path])
            return original(path, *rest)
        setattr(os, name, sealed_exec)


def unseal_programs():
    import subprocess
    if "Popen" in _unsealed:
        subprocess.Popen = _unsealed.pop("Popen")
    for name, original in list(_unsealed.items()):
        setattr(os, name, original)
    _unsealed.clear()


def pytest_configure(config):
    import tempfile
    seal_programs()
    scratch = tempfile.mkdtemp(prefix = "joybox-tests-")
    config.joybox_scratch = scratch
    if not os.environ.get("JOYBOX_TESTS_REAL_HOME"):
        config.joybox_home = (os.environ.get("HOME"), os.environ.get("USERPROFILE"))
        os.environ["HOME"] = scratch
        os.environ["USERPROFILE"] = scratch
    from joybox import settings, default_settings
    config_path = os.path.join(scratch, "JoyBox.ini")
    default_settings.create_default_config_file(config_path)
    settings.reset()
    settings.set_settings_file(config_path)


def pytest_unconfigure(config):
    import shutil
    unseal_programs()
    home = getattr(config, "joybox_home", None)
    if home:
        for name, value in zip(["HOME", "USERPROFILE"], home):
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    scratch = getattr(config, "joybox_scratch", None)
    if scratch:
        shutil.rmtree(scratch, ignore_errors = True)

###########################################################
# Hermetic baseline
#
# joybox.settings resolves its file at import time, preferring ~/JoyBox.ini.
# Left alone, every test reads whatever the developer happens to have
# configured, and the same test passes here and fails on a clean checkout.
# Point the whole session at a generated default config instead.
###########################################################

@pytest.fixture(scope = "session", autouse = True)
def session_home(tmp_path_factory):
    # Anything resolved from the home directory - the output log the logger
    # opens on first use, the cookie jar, the installed tool paths - otherwise
    # comes from the developer's own home, so the suite both reads and writes
    # the machine it runs on. A test that cares about the home sets its own;
    # this is only the floor.
    #
    # Tools are found under the home too, so this makes the requires_tool
    # integration tests skip exactly as they do on a clean checkout. Set
    # JOYBOX_TESTS_REAL_HOME=1 to run those against the real installation.
    if os.environ.get("JOYBOX_TESTS_REAL_HOME"):
        yield os.path.expanduser("~")
        return
    home = str(tmp_path_factory.mktemp("session_home"))
    patcher = pytest.MonkeyPatch()
    patcher.setenv("HOME", home)
    patcher.setenv("USERPROFILE", home)
    yield home
    patcher.undo()


@pytest.fixture(scope = "session", autouse = True)
def session_settings_file(tmp_path_factory, session_home):
    from joybox import settings, default_settings, serverinfo

    config_path = os.path.join(str(tmp_path_factory.mktemp("settings")), "JoyBox.ini")
    default_settings.create_default_config_file(config_path)
    settings.reset()
    settings.set_settings_file(config_path)
    return config_path


@pytest.fixture(autouse = True)
def no_outbound_network(monkeypatch, request):
    # A test that quietly reaches the internet passes on a connected machine
    # and fails in CI, and its result depends on a third party. Subprocess
    # based tests are unaffected; this only closes the in-process path.
    import socket

    if request.node.get_closest_marker("allow_network"):
        return

    def refuse(*args, **kwargs):
        raise RuntimeError(
            "outbound network access is not available to tests; "
            "mark the test with @pytest.mark.allow_network if it truly needs it")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture(scope = "session")
def hermetic_home(tmp_path_factory, session_settings_file):
    # A home directory for subprocesses, holding the same generated config so a
    # script started from the tests never reads the developer's own.
    import shutil

    home = tmp_path_factory.mktemp("home")
    shutil.copy(session_settings_file, os.path.join(str(home), "JoyBox.ini"))
    return str(home)


@pytest.fixture(scope = "session")
def hermetic_env(hermetic_home):
    env = dict(os.environ)
    env["HOME"] = hermetic_home
    env["USERPROFILE"] = hermetic_home
    return env


###########################################################
# Path fixtures
###########################################################

@pytest.fixture(scope = "session")
def repo_root():
    return REPO_ROOT

@pytest.fixture(scope = "session")
def shared_dir():
    return SHARED_DIR

@pytest.fixture(scope = "session")
def bootstrap_dir():
    return BOOTSTRAP_DIR

@pytest.fixture(scope = "session")
def installers_dir():
    return INSTALLERS_DIR

@pytest.fixture(scope = "session")
def scripts_bin_dir():
    return SCRIPTS_BIN_DIR

@pytest.fixture(scope = "session")
def installer_files():
    # Every installer module, as (name, path) pairs
    found = []
    for filename in sorted(os.listdir(INSTALLERS_DIR)):
        if filename.startswith("installer_") and filename.endswith(".py"):
            found.append((filename[:-3], os.path.join(INSTALLERS_DIR, filename)))
    return found

@pytest.fixture(scope = "session")
def script_files(scripts_bin_dir):
    # Every CLI entry point under Scripts/bin, as (name, path) pairs
    found = []
    for filename in sorted(os.listdir(scripts_bin_dir)):
        if filename.endswith(".py") and not filename.startswith("_"):
            found.append((filename[:-3], os.path.join(scripts_bin_dir, filename)))
    return found

###########################################################
# Settings isolation
#
# joybox.settings is process-global: a parser plus an in-memory overlay that
# set_value writes to. Without isolation a test that sets a value leaks it into
# every test that runs afterwards, in whatever order pytest happens to pick.
###########################################################

@pytest.fixture
def isolated_settings(tmp_path, session_settings_file):
    from joybox import settings, default_settings, serverinfo

    config_path = os.path.join(str(tmp_path), "JoyBox.ini")
    default_settings.create_default_config_file(config_path)

    settings.reset()
    settings.set_settings_file(config_path)

    # Values every server component expects to be non-empty
    settings.set_value("UserData.Servers", "server_0_domain_name", "joybox.test")
    settings.set_value("UserData.Servers", "server_0_domain_contact", "nobody@joybox.test")
    serverinfo.select_server(0)

    yield settings

    # Put the session baseline back, or the next test reads a tmp_path that
    # pytest has already taken away.
    settings.reset()
    settings.set_settings_file(session_settings_file)

###########################################################
# Connection double
###########################################################

@pytest.fixture
def recording_connection():
    from fakes import RecordingConnection
    return RecordingConnection()


###########################################################
# External tools
###########################################################

@pytest.fixture
def recording_command(monkeypatch):
    # Records what a wrapper would run instead of running it. Every disc image
    # wrapper goes through joybox.command, so this is the one seam.
    from fakes import RecordingCommand
    return RecordingCommand(monkeypatch)


def tool_path(name):
    from joybox import programs
    try:
        if not programs.is_tool_installed(name):
            return None
        return programs.get_tool_program(name)
    except Exception:
        return None


@pytest.fixture
def requires_tool(request):
    for marker in request.node.iter_markers("requires_tool"):
        for name in marker.args:
            if not tool_path(name):
                pytest.skip("%s is not installed" % name)
