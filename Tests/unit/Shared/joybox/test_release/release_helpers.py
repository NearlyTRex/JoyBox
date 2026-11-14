# Imports
import os

# Local imports
from joybox import release
from file_helpers import write

def asset(name):
    return {"name": name, "browser_download_url": "https://dl.example/" + name}


def release_with(*names):
    return {"assets": [asset(name) for name in names]}


def fetch(**kwargs):
    defaults = dict(
        github_user = "acme", github_repo = "tool",
        starts_with = "", ends_with = "",
        install_name = "Tool", install_dir = "/tools/Tool")
    defaults.update(kwargs)
    return release.download_github_release(**defaults)


def fetch_webpage(**kwargs):
    defaults = dict(
        webpage_url = "https://acme.example/downloads",
        webpage_base_url = "https://acme.example",
        starts_with = "", ends_with = "",
        install_name = "Tool", install_dir = "/tools/Tool")
    defaults.update(kwargs)
    return release.download_webpage_release(**defaults)


def setup_archive(workspace, archive_name = "Tool-1.0.zip", **kwargs):
    archive_file = write(os.path.join(str(workspace["root"]), "downloads", archive_name))
    defaults = dict(
        archive_file = archive_file,
        install_name = "Tool",
        install_dir = workspace["install_dir"])
    defaults.update(kwargs)
    return release.setup_general_release(**defaults)


def install_stored(archive_dir, **kwargs):
    defaults = dict(
        archive_dir = str(archive_dir),
        install_name = "Tool",
        install_dir = "/tools/Tool")
    defaults.update(kwargs)
    return release.setup_stored_release(**defaults)
