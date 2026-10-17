# Imports
import os
import configparser

# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths
import joybox.serialization as serialization
from joybox import platform_info

# Config files
config_files = {}

# Where each kind of Firefox install keeps its profiles
def get_profile_roots():
    if platform_info.is_windows_platform():
        return [os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox")]
    home = os.path.expanduser("~")
    return [
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
    ]

# Find the profile Firefox opens by default, or "" when there is none
# An install records the profile it uses in its [Install...] section; the
# Default=1 flag on a [Profile...] section is only what older Firefox used, and
# it can mark a profile nothing opens.
def find_default_profile_dir(profile_roots = None):
    for root in profile_roots if profile_roots is not None else get_profile_roots():
        text = serialization.read_text_file(os.path.join(root, "profiles.ini"))
        if not text:
            continue
        parser = configparser.ConfigParser(interpolation = None)
        try:
            parser.read_string(text)
        except configparser.Error:
            continue
        profile = ""
        for section in parser.sections():
            if section.startswith("Install") and parser[section].get("Default"):
                profile = parser[section]["Default"]
                break
        if not profile:
            for section in parser.sections():
                if section.startswith("Profile") and parser[section].get("Default") == "1":
                    profile = parser[section].get("Path", "")
                    break
        if not profile:
            continue
        profile_dir = profile if os.path.isabs(profile) else os.path.join(root, profile)
        if paths.does_path_exist(profile_dir):
            return profile_dir
    return ""

# Firefox tool
class Firefox(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Firefox"

    # Get config
    def get_config(self):

        # Get firefox info
        firefox_exe = settings.get_value("Tools.Firefox", "firefox_exe")
        firefox_install_dir = settings.get_path_value("Tools.Firefox", "firefox_install_dir")
        firefox_download_dir = settings.get_path_value("Tools.Firefox", "firefox_download_dir")
        firefox_profile_dir = settings.get_path_value("Tools.Firefox", "firefox_profile_dir", default_value = "", throw_exception = False)
        if not firefox_profile_dir:
            firefox_profile_dir = find_default_profile_dir()

        # Return config
        return {
            "Firefox": {
                "program": paths.join_paths(firefox_install_dir, firefox_exe),
                "download_dir": firefox_download_dir,
                "profile_dir": firefox_profile_dir
            }
        }
