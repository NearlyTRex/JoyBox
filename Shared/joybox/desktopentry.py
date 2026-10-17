# Desktop entries
#
# XDG .desktop files that run a JoyBox command: app menu launchers, written by
# a tool's configure step, and login autostart entries, written by the
# bootstrap. Both are built the same way.

# Imports
import os

# Local imports
import joybox.environment as environment
import joybox.fileops as fileops
import joybox.paths as paths
from joybox import platform_info

# Build the text of a desktop entry that runs a JoyBox command
def build_desktop_entry(name, description, command, extra_lines = ()):
    lines = [
        "[Desktop Entry]",
        "Type=Application",
        "Name=%s" % name,
        "Comment=%s" % description,
        "Exec=%s" % environment.get_command_path(command),
    ] + list(extra_lines)
    return "\n".join(lines) + "\n"

# Get where the app menu reads launchers from
def get_launchers_dir():
    return os.path.join(os.path.expanduser("~"), ".local", "share", "applications")

# Get a launcher's path
def get_launcher_path(filename):
    return os.path.join(get_launchers_dir(), filename)

# Put a launcher in the app menu, or take it out again, so a tool configured on
# a machine whose role no longer needs it leaves nothing behind. Only Linux
# desktops read these.
def set_launcher(
    enabled,
    filename,
    name,
    description,
    command,
    icon,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not platform_info.is_linux_platform():
        return True
    launcher_path = get_launcher_path(filename)
    if not enabled:
        if not paths.does_path_exist(launcher_path):
            return True
        return fileops.remove_file(
            src = launcher_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return fileops.touch_file(
        src = launcher_path,
        contents = build_desktop_entry(name, description, command,
            ["Icon=%s" % icon, "Categories=Game;", "Terminal=false"]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
