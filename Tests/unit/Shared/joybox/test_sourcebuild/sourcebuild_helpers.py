# Local imports
from joybox import sourcebuild

PATCH_BODY = "--- a/main.c\n+++ b/main.c\n"

GIT_URL = "https://github.com/acme/tool.git"
TARBALL_URL = "https://dl.example/tool-1.0.tar.gz"


def build_source(**kwargs):
    defaults = dict(release_url = GIT_URL, build_cmd = ["make"])
    defaults.update(kwargs)
    return sourcebuild.build_from_source(**defaults)


def build_binary(builder, **kwargs):
    defaults = dict(
        release_url = GIT_URL,
        build_cmd = ["make"],
        output_file = "tool",
        install_name = "Tool",
        install_dir = builder["install_dir"])
    defaults.update(kwargs)
    return sourcebuild.build_binary_from_source(**defaults)


def build_appimage(builder, **kwargs):
    defaults = dict(
        release_url = GIT_URL,
        build_cmd = ["make"],
        output_file = "Tool-x86_64.AppImage",
        install_name = "Tool",
        install_dir = builder["install_dir"])
    defaults.update(kwargs)
    return sourcebuild.build_appimage_from_source(**defaults)
