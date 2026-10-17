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
def installer(tmp_path, repo_root, shell_traced_env):
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
        environment = shell_traced_env(dict(os.environ,
            PATH = "%s:/usr/bin:/bin" % bin_dir,
            JOYBOX_DIR = str(checkout),
            JOYBOX_TEST_ARGS = str(args_file),
            JOYBOX_TEST_EXIT = str(exit_code)))
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


###########################################################
# install.sh on a bare machine
#
# The paths a fresh machine takes, run in the sandbox where the installer is
# root unless told otherwise and every package tool is a stub.
###########################################################

CHECKOUT = "/root/Repositories/JoyBox"

# A git whose HEAD moves on pull; a command named in $GIT_FAILS fails
FAKE_GIT = r"""for word in fetch checkout pull clone rev-parse; do
    case " $* " in *" $word "*) case " ${GIT_FAILS:-} " in *" $word "*) exit 1 ;; esac ;; esac
done
case " $* " in
    *" rev-parse "*) cat /root/head 2>/dev/null || echo abc123 ;;
    *" pull "*) echo "${GIT_PULLED_TO:-abc123}" > /root/head ;;
    *" clone "*) mkdir -p "${!#}/.git" ;;
esac
"""


@pytest.fixture
def bare(shell_sandbox):
    shell_sandbox.stub("git", script = FAKE_GIT)
    shell_sandbox.write(CHECKOUT + "/.git/HEAD", "ref: refs/heads/main\n")
    return shell_sandbox


def install_on(sandbox, **env):
    return sandbox.run("install.sh", "-a", "status", env = env)


def remove_command(sandbox, name):
    os.remove(os.path.join(sandbox.stub_dir, name))


def test_root_needs_no_sudo(bare):
    bare.stub("dpkg", code = 1)

    result = install_on(bare)

    assert result.returncode == 0, result.stdout + result.stderr
    assert bare.ran("apt-get", "install", "-y", "python3-venv")
    assert not bare.calls("sudo")


def test_without_apt_it_refuses_to_run(bare):
    remove_command(bare, "apt-get")

    result = install_on(bare)

    assert result.returncode == 1
    assert "apt-get' was not found" in result.stderr


def test_a_user_installs_prerequisites_through_sudo(bare):
    bare.stub("id", stdout = "1000\n")
    bare.stub("dpkg", code = 1)

    result = install_on(bare)

    assert result.returncode == 0, result.stdout + result.stderr
    assert bare.ran("sudo", "apt-get", "install", "-y", "python3-venv")


def test_a_user_without_sudo_cannot_install(bare):
    bare.stub("id", stdout = "1000\n")
    remove_command(bare, "sudo")

    result = install_on(bare)

    assert result.returncode == 1
    assert "neither root nor 'sudo'" in result.stderr


def test_every_missing_prerequisite_is_installed(bare):
    remove_command(bare, "python3")
    os.rename(os.path.join(bare.stub_dir, "git"), os.path.join(bare.stub_dir, ".git.pending"))
    bare.stub("dpkg", code = 1)
    # git and bootstrap.py still have to run once the packages are in
    bare.stub("apt-get", script = (
        'mv "${0%/*}/.git.pending" "${0%/*}/git" 2>/dev/null || true\n'
        'printf "#!/bin/bash\\n" > "${0%/*}/python3"; chmod +x "${0%/*}/python3"\n'))

    result = install_on(bare)

    assert result.returncode == 0, result.stdout + result.stderr
    assert bare.ran("apt-get", "install", "-y", "git", "python3", "python3-venv")


def test_present_prerequisites_are_not_reinstalled(bare):
    result = install_on(bare)

    assert "Prerequisites already present" in result.stdout
    assert not bare.calls("apt-get")


def test_an_existing_checkout_is_fast_forwarded(bare):
    result = install_on(bare, GIT_PULLED_TO = "def456")

    assert result.returncode == 0
    assert "Updated abc123 -> def456" in result.stdout


def test_an_up_to_date_checkout_says_so(bare):
    result = install_on(bare)

    assert "Already up to date (abc123)" in result.stdout


def test_a_checkout_without_a_readable_head_still_updates(bare):
    result = install_on(bare, GIT_FAILS = "rev-parse")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Already up to date (?)" in result.stdout


@pytest.mark.parametrize("failing, warning", [
    ("fetch", "git fetch failed"),
    ("checkout", "Could not switch to 'main'"),
    ("pull", "Could not fast-forward"),
])
def test_a_checkout_that_cannot_update_is_used_as_it_is(bare, failing, warning):
    result = install_on(bare, GIT_FAILS = failing)

    assert result.returncode == 0, result.stdout + result.stderr
    assert warning in result.stderr
    assert bare.ran("python3", "bootstrap.py", "-a", "status")


def test_a_missing_checkout_is_cloned(bare):
    result = install_on(bare, JOYBOX_DIR = "/srv/joybox/JoyBox", JOYBOX_REF = "dev")

    assert result.returncode == 0, result.stdout + result.stderr
    assert bare.ran("git", "clone", "--branch", "dev", "https://github.com/NearlyTRex/JoyBox.git", "/srv/joybox/JoyBox")


def test_a_directory_that_is_not_a_checkout_is_left_alone(bare):
    bare.write("/srv/other/notes.txt", "mine\n")

    result = install_on(bare, JOYBOX_DIR = "/srv/other")

    assert result.returncode == 1
    assert "is not a git checkout" in result.stderr
    assert not bare.calls("git")
