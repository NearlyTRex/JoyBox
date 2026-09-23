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
    description = "Install, update, or rebuild the third-party tools JoyBox depends on.",
    details = (
        "Installs the external programs other JoyBox commands call, such as 7-Zip, FFMpeg,\n"
        "RClone, Wine, Pegasus and the store downloaders (Legendary, Nile, LGOGDownloader).\n"
        "Each package is defined in `Shared/joybox/tools/` and knows how to download, install\n"
        "and optionally configure itself. Tools install under `[UserData.Dirs] tools_dir` in\n"
        "`~/JoyBox.ini`.\n"
        "\n"
        "For each selected package it removes the package's install directory first when\n"
        "`--force` is given, then installs it: downloaded by default, or from the copy backed\n"
        "up in the locker with `--offline`. With `--configure` it then runs the package's\n"
        "configuration step. `--clean` removes the whole tools directory once, before any\n"
        "package is installed.\n"
        "\n"
        "A program whose file is already in place is skipped, so re-running only fills in\n"
        "what is missing. This installs the programs JoyBox uses, not the JoyBox commands\n"
        "themselves, which come from the bootstrap."),
    examples = [
        ("Install every tool that is missing", "setup_tools"),
        ("Install specific tools", "setup_tools -k \"7-Zip,RClone,Wine\""),
        ("Rebuild two tools from scratch", "setup_tools -f -k \"RClone,FFMpeg\""),
        ("Wipe the tools directory and reinstall everything", "setup_tools --clean"),
        ("Install from the locker backups instead of downloading", "setup_tools --offline"),
        ("Install and configure Ghidra", "setup_tools -k Ghidra --configure"),
        ("Preview without changing anything", "setup_tools -p -v"),
    ],
    notes = [
        "Package names are matched exactly and are case-sensitive (`FFMpeg`, `7-Zip`, `YtDlp`); an unknown name is silently skipped.",
        "`--force` applies only to the selected packages; `--clean` wipes the whole tools directory. Use `--force` to update, `--clean` for a full rebuild.",
        "Installation stops at the first package that fails.",
        "`~/JoyBox.ini` must exist and symlinks must be supported, or the command exits before doing anything.",
    ],
    see_also = ["setup_game_emulators", "setup_game_assets"],
    section = "Setup & Installation")
parser.add_group("Selection")
parser.add_boolean_argument(args = ("-e", "--offline"), description = "Install from the copies backed up in the locker instead of downloading")
parser.add_boolean_argument(args = ("-c", "--configure"), description = "Run each package's configuration step after installing it")
parser.add_boolean_argument(args = ("--clean",), description = "Remove the entire tools directory before installing anything")
parser.add_boolean_argument(args = ("-f", "--force"), description = "Remove each selected package's install directory and reinstall it, even if already installed")
parser.add_string_argument(args = ("-k", "--packages"), description = "Comma-separated package names to install, e.g. `\"7-Zip,RClone\"`; all packages when omitted")
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

    # Setup tools
    setup.setup_tools(
        offline = args.offline,
        configure = args.configure,
        clean = args.clean,
        force = args.force,
        packages = packages,
        setup_params = setup_params)

# Start
if __name__ == "__main__":
    system.run_main(main)
