# Imports
import importlib.machinery
import importlib.util
import os

# Third-party imports
import pytest


###########################################################
# Pre-commit secret scan
#
# A false positive blocks a commit and teaches the habit of --no-verify, so
# what the scan lets through matters as much as what it stops.
###########################################################

HOOK_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", ".githooks", "pre-commit")


@pytest.fixture(scope = "module")
def hook():
    loader = importlib.machinery.SourceFileLoader("joybox_pre_commit", HOOK_PATH)
    spec = importlib.util.spec_from_loader("joybox_pre_commit", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def is_flagged(hook, line):
    for name, pattern in hook.SECRET_RES:
        match = pattern.search(line)
        if not match:
            continue
        if name == "Assigned secret" and hook.PLACEHOLDER_RE.match(match.group(2).strip()):
            continue
        return True
    return False


@pytest.mark.parametrize("line", [
    'PASSWORD="$(cat "$PASSWORD_FILE")"',
    'PASSWORD="$(op read op://Vault/Item/password)"',
    'PASSWORD="$PASSWORD_INPUT"',
    'password = "${ADMIN_PASSWORD}"',
    'token = "<your token>"',
])
def test_a_value_computed_at_run_time_is_not_a_secret(hook, line):
    assert not is_flagged(hook, line)


@pytest.mark.parametrize("line", [
    'PASSWORD="hunter2secret"',  # gitleaks:allow
    'api_key = "sk-live-0123456789"',  # gitleaks:allow
    'password: "correct horse battery"',  # gitleaks:allow
])
def test_a_literal_secret_is_still_caught(hook, line):
    assert is_flagged(hook, line)
