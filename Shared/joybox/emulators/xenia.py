# Local imports
from joybox import emulatorbase


# Xenia emulator
class Xenia(emulatorbase.EmulatorBase):

    NAME = "Xenia"

    # Write its config files under the emulators root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)
