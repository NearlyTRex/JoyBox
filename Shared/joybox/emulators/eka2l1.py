# Imports

# Local imports
from joybox import config
from joybox import emulatorbase

# EKA2L1 emulator
class EKA2L1(emulatorbase.EmulatorBase):

    NAME = "EKA2L1"

    # Write its config files, verify the locker system files, then unzip the data archive
    # into each platform's setup dir, keeping files already there
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        if not self.write_config_files(setup_params):
            return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["data"]:
                if not self.extract_system_archive(platform, obj, setup_params):
                    return False
        return True
