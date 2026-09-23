#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.arguments as arguments
import joybox.system as system
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Install, update, or rebuild the game emulators JoyBox manages.",
    details = (
        "Installs the emulators used to run the game collection, such as RetroArch, Dolphin,\n"
        "PCSX2, Citra, mGBA, melonDS, DuckStation, Cemu and Mame. Each emulator is defined in\n"
        "`Shared/joybox/emulators/` and knows how to download, install and optionally\n"
        "configure itself. Emulators install under `[UserData.Dirs] emulators_dir` in\n"
        "`~/JoyBox.ini`.\n"
        "\n"
        "For each selected emulator it removes the install directory first when `--force` is\n"
        "given, then installs it: downloaded by default, or from the copy backed up in the\n"
        "locker with `--offline`. With `--configure` it then runs the emulator's configuration\n"
        "step. `--clean` removes the whole emulators directory once, before anything is\n"
        "installed.\n"
        "\n"
        "An emulator whose program is already in place is skipped, so re-running only fills in\n"
        "what is missing. The interface is the same as `setup_tools`; only the package set and\n"
        "install directory differ."),
    examples = [
        ("Install every emulator that is missing", "setup_game_emulators"),
        ("Install specific emulators", "setup_game_emulators -k \"Dolphin,PCSX2,Citra\""),
        ("Rebuild a single emulator", "setup_game_emulators -f -k RetroArch"),
        ("Wipe the emulators directory and reinstall everything", "setup_game_emulators --clean"),
        ("Install from the locker backups, then configure", "setup_game_emulators --offline --configure"),
        ("Preview without changing anything", "setup_game_emulators -p -v"),
    ],
    notes = [
        "Emulator names are matched exactly and are case-sensitive (`FS-UAE`, `VICE-C64`, `mGBA`); an unknown name is silently skipped.",
        "`--force` applies only to the selected emulators; `--clean` wipes the whole emulators directory.",
        "Installation stops at the first emulator that fails.",
        "`~/JoyBox.ini` must exist and symlinks must be supported, or the command exits before doing anything.",
    ],
    see_also = ["setup_tools", "setup_game_assets"],
    section = "Setup & Installation")
parser.add_group("Selection")
parser.add_boolean_argument(args = ("-e", "--offline"), description = "Install from the copies backed up in the locker instead of downloading")
parser.add_boolean_argument(args = ("-c", "--configure"), description = "Run each emulator's configuration step after installing it")
parser.add_boolean_argument(args = ("--clean",), description = "Remove the entire emulators directory before installing anything")
parser.add_boolean_argument(args = ("-f", "--force"), description = "Remove each selected emulator's install directory and reinstall it, even if already installed")
parser.add_string_argument(args = ("-k", "--packages"), description = "Comma-separated emulator names to install, e.g. `\"Dolphin,PCSX2\"`; all emulators when omitted")
parser.add_group("Backup")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.ALL,
    description = "Locker to back downloaded release files up to")
parser.add_boolean_argument(args = ("-s", "--skip_autobackup"), description = "Do not back downloaded release files up to the locker")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Parse package list
    packages = None
    if args.packages:
        packages = [p.strip() for p in args.packages.split(",")]

    # Create setup params from args
    setup_params = config.SetupParams.from_args(args)

    # Setup emulators
    setup.setup_emulators(
        offline = args.offline,
        configure = args.configure,
        clean = args.clean,
        force = args.force,
        packages = packages,
        setup_params = setup_params)

# Start
if __name__ == "__main__":
    system.run_main(main)
