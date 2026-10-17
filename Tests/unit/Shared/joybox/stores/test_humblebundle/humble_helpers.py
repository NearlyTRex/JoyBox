# Imports
import json

PYTHON = "/tools/venv/python"
MANAGER = "/tools/humble/humblebundle.py"

MANAGER_TOOLS = {"PythonVenvPython": PYTHON, "HumbleBundleManager": MANAGER}

MANAGER_CMD = [PYTHON, MANAGER, "--auth", "token123"]


def show_cmd(appname):
    return MANAGER_CMD + ["--show", appname, "--json", "--quiet"]


def game(name, *downloads):
    return {"human_name": name, "downloads": list(downloads)}


def download(platform, *timestamps):
    return {"platform": platform, "download_struct": [{"timestamp": stamp} for stamp in timestamps]}


# Answers each command by what it asks for, so purchases can be listed and described
class ManagerOutput:

    def __init__(self, listing, games):
        self.listing = listing
        self.games = games

    def __call__(self, cmd, **kwargs):
        if "--list" in cmd:
            return self.listing
        appname = cmd[cmd.index("--show") + 1]
        details = self.games.get(appname, "")
        return details if isinstance(details, str) else json.dumps(details)
