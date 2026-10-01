# Imports
import os

# Local imports
from joybox import release

PATCH_BODY = "--- a/main.c\n+++ b/main.c\n"

GIT_URL = "https://github.com/acme/tool.git"
TARBALL_URL = "https://dl.example/tool-1.0.tar.gz"


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


def write(path, contents = "data"):
    path = str(path)
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "w") as handle:
        handle.write(contents)
    return path


def tree(root):
    found = []
    for directory, _, filenames in os.walk(str(root)):
        for filename in filenames:
            found.append(os.path.relpath(os.path.join(directory, filename), str(root)))
    return sorted(found)


def failing(*args, **kwargs):
    return False


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


def build_source(**kwargs):
    defaults = dict(release_url = GIT_URL, build_cmd = ["make"])
    defaults.update(kwargs)
    return release.build_from_source(**defaults)


def build_binary(builder, **kwargs):
    defaults = dict(
        release_url = GIT_URL,
        build_cmd = ["make"],
        output_file = "tool",
        install_name = "Tool",
        install_dir = builder["install_dir"])
    defaults.update(kwargs)
    return release.build_binary_from_source(**defaults)


def build_appimage(builder, **kwargs):
    defaults = dict(
        release_url = GIT_URL,
        build_cmd = ["make"],
        output_file = "Tool-x86_64.AppImage",
        install_name = "Tool",
        install_dir = builder["install_dir"])
    defaults.update(kwargs)
    return release.build_appimage_from_source(**defaults)
