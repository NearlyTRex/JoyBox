# Local imports
from joybox import config
from joybox import programs
from joybox import gui
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

    # The launch command: the program with its ini path, the rom path and launch file, and
    # -window unless fullscreen is asked; shows an error popup when the platform is not one Mame plays
    def get_launch_command(self, game_info, fullscreen = False):
        game_platform = game_info.get_platform()

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
