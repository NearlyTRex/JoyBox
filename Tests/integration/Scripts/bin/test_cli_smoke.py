# Imports
import os
import subprocess
import sys

# Third-party imports
import pytest


###########################################################
# CLI smoke
#
# Every entry point is launched as a real subprocess with --help. For a thin
# wrapper this is the test that matters: it proves the imports resolve, the
# argument parser is well formed, and the joybox modules it reaches for still
# exist. Those are the realistic ways a wrapper breaks.
###########################################################

HELP_TIMEOUT_SECONDS = 60


def run_help(path, repo_root):
    return subprocess.run(
        [sys.executable, path, "--help"],
        capture_output = True,
        text = True,
        timeout = HELP_TIMEOUT_SECONDS,
        cwd = repo_root)


def script_parameters(scripts_bin_dir):
    names = sorted(
        filename for filename in os.listdir(scripts_bin_dir)
        if filename.endswith(".py") and not filename.startswith("_"))
    return [(name, os.path.join(scripts_bin_dir, name)) for name in names]


def pytest_generate_tests(metafunc):

    # Parametrized from the directory rather than a session fixture, so a new
    # script is picked up without touching this file.
    #
    # The paths come from conftest rather than being recomputed here: Tests/
    # mirrors the repo layout, so walking up looking for a "Scripts" directory
    # finds Tests/integration/Scripts instead of the real one.
    if "script_name" in metafunc.fixturenames:
        from conftest import SCRIPTS_BIN_DIR
        parameters = script_parameters(SCRIPTS_BIN_DIR)
        metafunc.parametrize(
            "script_name,script_path",
            parameters,
            ids = [name for name, _ in parameters])


@pytest.mark.slow
def test_help_exits_cleanly(script_name, script_path, repo_root):
    result = run_help(script_path, repo_root)

    assert result.returncode == 0, (
        f"{script_name} --help exited {result.returncode}\n"
        f"stdout:\n{result.stdout[-2000:]}\n"
        f"stderr:\n{result.stderr[-2000:]}")


@pytest.mark.slow
def test_help_does_not_traceback(script_name, script_path, repo_root):
    result = run_help(script_path, repo_root)
    combined = result.stdout + result.stderr

    assert "Traceback (most recent call last)" not in combined, (
        f"{script_name} --help raised:\n{combined[-2000:]}")


@pytest.mark.slow
def test_help_describes_the_script(script_name, script_path, repo_root):

    # argparse always emits a usage line. Its absence means the parser was
    # never reached, which usually means an import failed silently.
    result = run_help(script_path, repo_root)
    combined = result.stdout + result.stderr

    assert "usage:" in combined.lower(), \
        f"{script_name} --help printed no usage line:\n{combined[-1000:]}"
