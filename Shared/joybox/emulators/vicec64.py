# Local imports
from joybox import emulatorbase


# ViceC64 emulator
class ViceC64(emulatorbase.EmulatorBase):

    NAME = "VICE-C64"

    # Write its config files under the emulators root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)
