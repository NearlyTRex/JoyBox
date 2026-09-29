# Imports
import os
import pty
import fcntl
import termios
import subprocess

# Third-party imports
import pytest


###########################################################
# install.sh
#
# The curl | bash entry point runs before the repo exists, so it stays shell.
# It runs here against stand-in git, dpkg and python3 on PATH, with the
# checkout already present, and the arguments bootstrap.py would have received
# are read back from the fake python3.
###########################################################

FAKE_COMMANDS = {
    "git": 'if [ "$1" = "-C" ] && [ "$3" = "rev-parse" ]; then echo abc123; fi\n',
    "dpkg": "",
    "python3": 'printf "%s\\n" "$@" > "$JOYBOX_TEST_ARGS"\n[ -t 0 ] && echo tty > "$JOYBOX_TEST_ARGS.stdin"\nexit "${JOYBOX_TEST_EXIT:-0}"\n',
}


@pytest.fixture
def installer(tmp_path, repo_root):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in FAKE_COMMANDS.items():
        path = bin_dir / name
        path.write_text("#!/bin/bash\n" + body)
        path.chmod(0o755)

    checkout = tmp_path / "JoyBox"
    (checkout / ".git").mkdir(parents = True)
    args_file = tmp_path / "bootstrap-args"

    def run(*args, with_terminal = False, exit_code = 0):
        environment = dict(os.environ,
            PATH = "%s:/usr/bin:/bin" % bin_dir,
            JOYBOX_DIR = str(checkout),
            JOYBOX_TEST_ARGS = str(args_file),
            JOYBOX_TEST_EXIT = str(exit_code))
        command = ["bash", os.path.join(repo_root, "install.sh")] + list(args)
        if with_terminal:
            result = run_on_terminal(command, environment)
        else:
            result = subprocess.run(command, env = environment, stdin = subprocess.DEVNULL,
                capture_output = True, start_new_session = True, timeout = 30, check = False)
        passed = args_file.read_text().splitlines() if args_file.exists() else None
        on_tty = os.path.exists(str(args_file) + ".stdin")
        return result.returncode, passed, on_tty
    return run


# Give the script a controlling terminal of its own, as a user's shell would
def run_on_terminal(command, environment):
    leader, follower = pty.openpty()

    def take_terminal():
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    try:
        process = subprocess.Popen(command, env = environment, stdin = follower,
            stdout = follower, stderr = follower, start_new_session = True,
            preexec_fn = take_terminal)
        os.close(follower)
        follower = None
        while True:
            try:
                if not os.read(leader, 4096):
                    break
            except OSError:
                break
        process.wait(timeout = 30)
        return process
    finally:
        if follower is not None:
            os.close(follower)
        os.close(leader)


def test_with_a_terminal_it_asks_which_components_to_install(installer):
    code, passed, on_tty = installer(with_terminal = True)

    assert code == 0
    assert passed == ["bootstrap.py", "-a", "setup", "-t", "local_ubuntu", "--interactive"]
    assert on_tty, "the menu has to read the terminal, not the piped script"


def test_without_a_terminal_it_installs_everything(installer):
    # cloud-init and CI: /dev/tty exists but cannot be opened.
    code, passed, on_tty = installer()

    assert code == 0
    assert passed == ["bootstrap.py", "-a", "setup", "-t", "local_ubuntu"]


def test_given_arguments_are_passed_through_unchanged(installer):
    code, passed, on_tty = installer("-a", "status", "-t", "local_ubuntu", with_terminal = True)

    assert code == 0
    assert passed == ["bootstrap.py", "-a", "status", "-t", "local_ubuntu"]


def test_a_failed_bootstrap_fails_the_installer(installer):
    code, passed, on_tty = installer(exit_code = 1)

    assert code != 0
