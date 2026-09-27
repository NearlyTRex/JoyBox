# Imports
import ast
import glob
import inspect
import os

# Local imports
from joybox import network, release


###########################################################
# Calls into the download helpers
#
# Tool setup only runs when a tool is installed, so a keyword a helper does
# not take (a branch passed to a release download, say) would only surface as
# a crash on someone's machine.
###########################################################

HELPERS = {
    "network.download_github_repository": network.download_github_repository,
    "network.archive_github_repository": network.archive_github_repository,
    "release.download_github_release": release.download_github_release,
}


def test_every_keyword_is_one_the_helper_takes(shared_dir):
    wrong = []
    for path in sorted(glob.glob(os.path.join(shared_dir, "joybox", "tools", "*.py"))):
        for node in ast.walk(ast.parse(open(path).read())):
            if not isinstance(node, ast.Call):
                continue
            helper = HELPERS.get(ast.unparse(node.func))
            if helper is None:
                continue
            accepted = inspect.signature(helper).parameters
            for keyword in node.keywords:
                if keyword.arg not in accepted:
                    wrong.append("%s:%d %s(%s=)" % (
                        os.path.basename(path), node.lineno, ast.unparse(node.func), keyword.arg))
    assert not wrong, "keywords the helper does not take:\n  " + "\n  ".join(wrong)
