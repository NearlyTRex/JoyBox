# Local imports
from joybox import config
from joybox import environment
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import programs
from joybox import gui
from joybox import emulatorcommon
from joybox import emulatorbase


# System drivers and media flags for non-arcade platforms
system_drivers = {
    config.Platform.OTHER_ATARI_5200: ("a5200", "-cart"),
    config.Platform.OTHER_ATARI_7800: ("a7800", "-cart"),
    config.Platform.OTHER_MAGNAVOX_ODYSSEY_2: ("odyssey2", "-cart"),
    config.Platform.OTHER_MATTEL_INTELLIVISION: ("intv", "-cart"),
    config.Platform.OTHER_PHILIPS_CDI: ("cdimono1", "-cdrom"),
    config.Platform.OTHER_TEXAS_INSTRUMENTS_TI994A: ("ti99_4a", "-cart"),
    config.Platform.OTHER_TIGER_GAMECOM: ("gamecom", "-cart1")
}

# The rom path and launch file arguments: the game dir and set name for arcade games,
# else the roms dir, the platform's system driver and its media flag with the game file
def get_rom_args(game_platform):
    if game_platform == config.Platform.OTHER_ARCADE:
        return [
            "-rompath", config.TOKEN_GAME_DIR,
            config.TOKEN_GAME_NAME
        ]
    system_name, media_flag = system_drivers[game_platform]
    return [
        "-rompath", programs.get_emulator_path_config_value("Mame", "roms_dir"),
        system_name,
        media_flag, config.TOKEN_GAME_FILE
    ]

# Mame emulator
class Mame(emulatorbase.EmulatorBase):

    NAME = "Mame"

    # Write its config files, then verify the locker system files and copy them into each platform's setup dir
    def configure(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        if not self.write_config_files(setup_params):
            return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Mame"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("Mame", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup Mame system files")
                    return False
        return True

    # The launch command: the program with its ini path, the rom path and launch file, and
    # -window unless fullscreen is asked; shows an error popup when the platform is not one Mame plays
    def get_launch_cmd(self, game_platform, fullscreen):

        # Check if this platform is valid
        if game_platform not in self.get_platforms():
            gui.display_error_popup(
                title_text = "Launch platform not defined",
                message_text = "Launch platform %s not defined in Mame config" % game_platform)

        # Get launch command
        launch_cmd = [programs.get_emulator_program("Mame")]

        # Add ini path
        launch_cmd += [
            "-inipath", programs.get_emulator_path_config_value("Mame", "config_dir")
        ]

        # Add rom path and launch file
        launch_cmd += get_rom_args(game_platform)

        # Mame runs fullscreen unless told otherwise
        if not fullscreen:
            launch_cmd += [
                "-window"
            ]
        return launch_cmd

    # Run MAME with its ini path; arcade games load by set name from the game dir, other platforms
    # through their system driver and media flag; windowed unless fullscreen is asked
    def launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = self.get_launch_cmd(game_info.get_platform(), fullscreen)

        # Launch game
        return emulatorcommon.simple_launch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
