#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.system as system
import joybox.playstation as playstation
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Check that PlayStation 3 disc CHDs decrypt and extract with their disc keys.",
    details = (
        "Finds every `.chd` file under the input path (or takes the one file given) and, with\n"
        "`-e`, checks it by doing a full round trip in a temporary directory: chdman extracts\n"
        "the disc image, PS3Dec decrypts it with the key in `<name>.dkey` next to the CHD, and\n"
        "the decrypted image is unpacked. If the unpacked disc has a `PS3_GAME/LICDIR/LIC.DAT`\n"
        "or `PS3_GAME/USRDIR/EBOOT.BIN`, its header is checked (`PS3LICDA` and `SCE`), since a\n"
        "wrong key still produces output but garbles these files.\n"
        "\n"
        "Nothing next to the CHD is written or changed."),
    examples = [
        ("Verify every PS3 CHD in a folder", "ps3_rom_tool -i /path/to/ps3 -e"),
        ("Verify one disc and stop at the first failure", "ps3_rom_tool -i \"/path/to/Game (USA).chd\" -e -x"),
    ],
    notes = [
        "Each disc is extracted, decrypted and unpacked in full, so the temporary directory needs room for about three times the disc's size.",
        "chdman (MameChdman) and PS3Dec must be installed as JoyBox tools.",
    ],
    see_also = ["chdverify", "chdextract", "psn_rom_tool"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "A PS3 `.chd` file, or a directory searched recursively for them; must exist")
parser.add_boolean_argument(args = ("-e", "--verify_chd"), description = "Verify each CHD by decrypting and unpacking it with its `.dkey` file; without it nothing is done")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: Verify CHD"
        ]
        if not prompts.prompt_for_preview("PS3 ROM tool", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Find rom files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".chd"]):

        # Verify chd
        if args.verify_chd:
            playstation.verify_ps3_chd(
                chd_file = file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
