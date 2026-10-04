# Imports
import os
import subprocess
import sys

# Third-party imports
import pytest


###########################################################
# CLI smoke
#
# Launching each command with --help proves the imports resolve, the parser is
# well formed, and the joybox modules it reaches for still exist.
###########################################################

HELP_TIMEOUT_SECONDS = 60


def run_help(module_name, repo_root, env):
    # Commands resolve JoyBox.ini from the home directory, so a run without a
    # hermetic home reads the developer's own configuration.
    from conftest import SHARED_DIR
    env = dict(env, PYTHONPATH = SHARED_DIR)
    return subprocess.run(
        [sys.executable, "-m", module_name, "--help"],
        capture_output = True,
        text = True,
        timeout = HELP_TIMEOUT_SECONDS,
        cwd = repo_root,
        env = env, check = False)


def pytest_generate_tests(metafunc):
    # Parametrized from the package so a new command is picked up automatically
    if "script_name" in metafunc.fixturenames:
        from conftest import find_cli_files
        parameters = [(name, "joybox.cli." + name) for name, _ in find_cli_files()]
        metafunc.parametrize(
            "script_name,script_path",
            parameters,
            ids = [name for name, _ in parameters])


@pytest.mark.slow
def test_help_exits_cleanly(script_name, script_path, repo_root, hermetic_env):
    result = run_help(script_path, repo_root, hermetic_env)

    assert result.returncode == 0, (
        f"{script_name} --help exited {result.returncode}\n"
        f"stdout:\n{result.stdout[-2000:]}\n"
        f"stderr:\n{result.stderr[-2000:]}")


@pytest.mark.slow
def test_help_does_not_traceback(script_name, script_path, repo_root, hermetic_env):
    result = run_help(script_path, repo_root, hermetic_env)
    combined = result.stdout + result.stderr

    assert "Traceback (most recent call last)" not in combined, (
        f"{script_name} --help raised:\n{combined[-2000:]}")


@pytest.mark.slow
def test_help_describes_the_script(script_name, script_path, repo_root, hermetic_env):
    # A missing usage line means the parser was never reached.
    result = run_help(script_path, repo_root, hermetic_env)
    combined = result.stdout + result.stderr

    assert "usage:" in combined.lower(), \
        f"{script_name} --help printed no usage line:\n{combined[-1000:]}"

###########################################################
# Previewing a seed
#
# The answer to "did I fill the ini in correctly" should not be a three
# gigabyte download and a build, so the entry point can render what the
# configuration produces and stop.
###########################################################

SEED_TIMEOUT_SECONDS = 60

INI = """[UserData.Autoinstall]
autoinstall_username = homelab
autoinstall_hostname = llm
autoinstall_ssh_keys = ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA homelab@example.com
autoinstall_packages = curl, git
"""


def run_show_seed(repo_root, env, extra = None):
    from conftest import SHARED_DIR
    env = dict(env, PYTHONPATH = SHARED_DIR)
    return subprocess.run(
        [sys.executable, "-m", "joybox.cli.build_autoinstall_iso", "--show_seed"] + (extra or []),
        capture_output = True,
        text = True,
        timeout = SEED_TIMEOUT_SECONDS,
        cwd = repo_root,
        env = env, check = False)


def env_with_home(hermetic_env, home):
    # hermetic_env is session scoped and its home already holds a generated
    # config, so writing into it would hand every later subprocess test this
    # one's configuration.
    env = dict(hermetic_env)
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    return env


@pytest.fixture
def incomplete_env(hermetic_env, tmp_path):
    # A config that exists but has not been filled in, which is the state a
    # fresh checkout is in.
    with open(os.path.join(str(tmp_path), "JoyBox.ini"), "w") as handle:
        handle.write("[UserData.Autoinstall]\nautoinstall_hostname = ubuntu\n")
    return env_with_home(hermetic_env, tmp_path)


@pytest.fixture
def configured_env(hermetic_env, tmp_path):
    with open(os.path.join(str(tmp_path), "JoyBox.ini"), "w") as handle:
        handle.write(INI)
    return env_with_home(hermetic_env, tmp_path)


@pytest.mark.slow
def test_a_seed_can_be_previewed_without_downloading_anything(repo_root, configured_env):
    result = run_show_seed(repo_root, configured_env)

    assert result.returncode == 0
    assert result.stdout.startswith("#cloud-config")
    assert "homelab" in result.stdout
    assert "local-hostname: llm" in result.stdout
    assert "'%s'" % " git" not in result.stdout


@pytest.mark.slow
def test_a_previewed_seed_carries_the_overlay(repo_root, configured_env):
    overlay = os.path.join(repo_root, "Scripts", "autoinstall", "homelab_llm.yaml")

    result = run_show_seed(repo_root, configured_env, ["--overlay", overlay])

    assert result.returncode == 0
    assert "ollama.com/install.sh" in result.stdout
    assert "nvidia-headless-no-dkms-580-server" in result.stdout


@pytest.mark.slow
def test_a_preview_says_what_the_configuration_is_missing(repo_root, incomplete_env):
    # An empty configuration is the state a fresh checkout is in, and the
    # point of the preview is to say so rather than to build something that
    # stops and waits at the target machine.
    result = run_show_seed(repo_root, incomplete_env)
    combined = result.stdout + result.stderr

    assert "autoinstall_username" in combined
