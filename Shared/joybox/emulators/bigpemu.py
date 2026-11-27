# Local imports
from joybox import emulatorbase


# BigPEmu emulator
class BigPEmu(emulatorbase.EmulatorBase):

    NAME = "BigPEmu"

    # Write its config files under the emulators root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)
