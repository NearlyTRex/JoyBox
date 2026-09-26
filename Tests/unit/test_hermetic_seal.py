# Imports
import os
import subprocess

# Third-party imports
import pytest

# Local imports
from joybox import secretstore, settings

# Captured while this module is imported, during collection and before any
# fixture has run: a module that builds something at import time sees this
COLLECTION_HOME = os.environ.get("HOME", "")
COLLECTION_SETTINGS_FILE = settings.get_settings_file()
COLLECTION_POPEN = subprocess.Popen.__name__


###########################################################
# The hermetic seal
#
# conftest refuses the programs that would reach past the test: privilege,
# the password manager, other machines, and this machine's services and VMs.
###########################################################

@pytest.mark.parametrize("args", [
    ["sudo", "true"],
    ["/usr/bin/sudo", "rm", "-rf", "/nonexistent"],
    ["op", "read", "op://Vault/Item/field"],
    ["virsh", "list"],
    ["ssh", "host.test", "true"],
])
def test_a_sealed_program_is_refused(args):
    with pytest.raises(RuntimeError, match = "may not run"):
        subprocess.run(args)


def test_a_sealed_program_in_a_shell_string_is_refused():
    with pytest.raises(RuntimeError, match = "may not run"):
        subprocess.run("LANG=C sudo true", shell = True)


def test_os_system_is_sealed_too():
    with pytest.raises(RuntimeError, match = "may not run"):
        os.system("sudo true")


def test_an_ordinary_program_still_runs():
    assert subprocess.run(["true"]).returncode == 0


def test_a_secret_reference_never_reaches_the_vault(monkeypatch):
    # Even with the tool found, resolving goes through a refused subprocess
    # and comes back empty rather than prompting to unlock.
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    secretstore.clear_resolved_secrets()

    assert secretstore.resolve_secret_reference("op://Vault/Item/field") is None


###########################################################
# Collection
###########################################################

@pytest.mark.skipif(bool(os.environ.get("JOYBOX_TESTS_REAL_HOME")), reason = "the real home was asked for")
def test_collection_does_not_run_in_the_developers_home():
    assert "joybox-tests-" in COLLECTION_HOME


def test_collection_reads_a_generated_settings_file():
    assert "joybox-tests-" in COLLECTION_SETTINGS_FILE


def test_collection_is_already_sealed():
    assert COLLECTION_POPEN == "SealedPopen"


def test_the_generated_settings_hold_no_secret_references():
    with open(COLLECTION_SETTINGS_FILE, "r") as config:
        assert "op://" not in config.read()
