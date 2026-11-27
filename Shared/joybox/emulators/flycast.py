# Local imports
from joybox import emulatorbase


# Flycast emulator
class Flycast(emulatorbase.EmulatorBase):

    NAME = "Flycast"

    # Write its config files under the emulators root
    def configure(self, setup_params = None):

        # Use default params if not provided
        return self.write_config_files(setup_params)
