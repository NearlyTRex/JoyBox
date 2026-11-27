# Local imports
from joybox import emulatorbase


# PPSSPP emulator
class PPSSPP(emulatorbase.EmulatorBase):

    NAME = "PPSSPP"

    # Write its config files under the emulators root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)
