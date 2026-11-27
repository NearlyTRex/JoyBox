# Local imports
from joybox import emulatorbase


# Atari800 emulator
class Atari800(emulatorbase.EmulatorBase):

    NAME = "Atari800"

    # Write its config files under the emulators root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)
