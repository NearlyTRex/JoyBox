# Imports
import string

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.gamemic as gamemic
from . import installer_managedfiles

# PipeWire config drop-ins, from Bootstrap/pipewire
MIC_FILE = "99-joybox-game-mic.conf"
PULSE_FILE = "99-joybox-game-mic-pulse.conf"
PIPEWIRE_FILES = (
    (MIC_FILE, "~/.config/pipewire/pipewire.conf.d/99-joybox-game-mic.conf", "pipewire"),
    (PULSE_FILE, "~/.config/pipewire/pipewire-pulse.conf.d/99-joybox-game-mic.conf", "pipewire-pulse"),
)

# Silent game mic and the rule that keeps games off every mic's volume, as PipeWire drop-ins
class Pipewire(installer_managedfiles.ManagedFiles):
    label = "PipeWire configuration"
    data_folder = "pipewire"
    files = PIPEWIRE_FILES

    # Desktop audio only exists on a local machine
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # The silent mic only in silent mode, the volume lock unless the game mic is off
    def get_active_files(self):
        mode = gamemic.get_mode()
        if mode == gamemic.MODE_SILENT:
            return [MIC_FILE, PULSE_FILE]
        if mode == gamemic.MODE_LOCKED:
            return [PULSE_FILE]
        return []

    # Exclude protected apps from the volume lock, and lock outputs when asked
    def render(self, name, contents):
        if name != PULSE_FILE:
            return contents
        protect = ""
        protected = gamemic.get_protected_apps()
        if protected:
            pattern = gamemic.quote_spa_string("!~" + gamemic.get_names_pattern(protected))
            protect = " application.process.binary = %s application.name = %s" % (pattern, pattern)
        quirks = ["block-source-volume"]
        if gamemic.is_output_locked():
            quirks.append("block-sink-volume")
        return string.Template(contents).safe_substitute(protect = protect, quirks = " ".join(quirks))
