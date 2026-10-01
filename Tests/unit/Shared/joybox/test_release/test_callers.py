# Imports
import ast
import os

# Third-party imports
import pytest

# Local imports
import joybox


###########################################################
# Setup callers
#
# A download is backed up to the locker the setup was asked for; a call that
# leaves locker_type out silently backs up to the default locker instead.
###########################################################

DOWNLOADERS = {"download_github_release", "download_webpage_release", "download_general_release"}
PACKAGE_DIR = os.path.dirname(joybox.__file__)


def find_download_calls():
    calls = []
    for folder in ["tools", "emulators"]:
        root = os.path.join(PACKAGE_DIR, folder)
        for name in sorted(os.listdir(root)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding = "utf-8") as handle:
                tree = ast.parse(handle.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in DOWNLOADERS:
                    calls.append(pytest.param(node, id = "%s/%s:%d" % (folder, name, node.lineno)))
    return calls


def test_tools_and_emulators_download_releases():
    assert find_download_calls()


@pytest.mark.parametrize("call", find_download_calls())
def test_every_setup_download_passes_its_locker(call):
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}

    assert "locker_type" in keywords
    assert ast.unparse(keywords["locker_type"]) == "setup_params.locker_type"
