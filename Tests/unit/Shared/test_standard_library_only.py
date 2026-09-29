# Imports
import subprocess
import sys


###########################################################
# Standard library only at import time
#
# bootstrap.py runs on a fresh machine's system python, before the venv and its
# packages exist, so no joybox module may import a third-party package at module
# level. Those imports belong inside the function that needs them.
###########################################################

IMPORT_EVERYTHING = """
import importlib, pkgutil, sys
sys.path.insert(0, sys.argv[1])
import joybox
failed = []
for module in pkgutil.walk_packages(joybox.__path__, prefix = "joybox."):
    try:
        importlib.import_module(module.name)
    except ImportError as error:
        failed.append("%s: %s" % (module.name, error))
print("\\n".join(failed))
"""


def test_every_module_imports_without_site_packages(shared_dir):
    # -S drops site-packages and -I ignores the environment, leaving only the
    # standard library, as on a machine that has never run the bootstrap
    result = subprocess.run(
        [sys.executable, "-S", "-I", "-c", IMPORT_EVERYTHING, shared_dir],
        capture_output = True, text = True, timeout = 120, check = False)

    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "", "modules needing a third-party package at import:\n" + result.stdout
