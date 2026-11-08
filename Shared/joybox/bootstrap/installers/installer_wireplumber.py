# Imports
import string

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.gamemic as gamemic
from . import installer_managedfiles

# WirePlumber 0.4 policy config and the scripts it loads, from Bootstrap/wireplumber
POLICY_FILE = "99-joybox-game-mic.lua"
WIREPLUMBER_FILES = (
    (POLICY_FILE, "~/.config/wireplumber/policy.lua.d/99-joybox-game-mic.lua", "wireplumber"),
    ("joybox-game-mic.lua", "~/.config/wireplumber/scripts/joybox-game-mic.lua", "wireplumber"),
)

# Policy config and script that keep Wine/Proton game recordings on the silent game mic
class Wireplumber(installer_managedfiles.ManagedFiles):
    label = "WirePlumber configuration"
    data_folder = "wireplumber"
    files = WIREPLUMBER_FILES
    safe_services = ("wireplumber",)

    # Desktop audio only exists on a local machine
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # Pinning only happens in silent mode
    def get_active_files(self):
        if gamemic.get_mode() == gamemic.MODE_SILENT:
            return [name for name, _, _ in self.files]
        return []

    # Hand the allowed games and protected apps to the script
    def render(self, name, contents):
        if name != POLICY_FILE:
            return contents
        return string.Template(contents).safe_substitute(
            allow = gamemic.escape_lua_string(",".join(gamemic.get_allowed_apps())),
            protect = gamemic.escape_lua_string(",".join(gamemic.get_protected_apps())))
