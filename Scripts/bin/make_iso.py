#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.archive as archive
import joybox.iso as iso
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Build an ISO image from each folder, or each zip file, in a directory.",
    details = (
        "With the default `-t Folder`, every folder directly inside the input directory becomes\n"
        "`<folder>.iso` in the input directory. Subfolders further down are part of their\n"
        "parent's image, not images of their own.\n"
        "\n"
        "With `-t Zip`, every `.zip` file under the input directory (searched recursively) is\n"
        "extracted to a `<name>_extracted` folder beside it and that folder becomes `<name>.iso`\n"
        "beside the zip. Without `-d` the `_extracted` folder is left in place.\n"
        "\n"
        "Images are made with xorriso in mkisofs mode: ISO level 3 with Joliet names. An image\n"
        "whose `.iso` already exists is skipped. The volume name is `-n`, or the folder or zip\n"
        "name with `-a`, or xorriso's default when neither is given.\n"
        "\n"
        "There is no confirmation prompt; the tool starts straight away."),
    examples = [
        ("Make an ISO from every folder in a directory, named after each folder", "make_iso -i /path/to/folders -a"),
        ("Make ISOs from zip files and delete the zips and extracted folders, previewing first", "make_iso -i /path/to/zips -t Zip -a -d -p -v"),
        ("Make ISOs with a fixed volume name", "make_iso -i /path/to/folders -n GAMEDISC"),
    ],
    notes = [
        "With `-d`, `-t Folder` deletes each source folder once its image is made, and `-t Zip` deletes each zip after extracting it and the extracted folder once the image is made.",
        "xorriso (XorrISO) and, for `-t Zip`, 7-Zip must be installed as JoyBox tools.",
    ],
    see_also = ["isoextract", "compress_folders", "chdconvert"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "Directory holding the folders or zip files to turn into images; must exist")
parser.add_enum_argument(
    args = ("-t", "--disc_source_type"),
    arg_type = config.DiscSourceType,
    default = config.DiscSourceType.FOLDER,
    description = "`Folder` images each top-level folder; `Zip` images the contents of each zip file")
parser.add_string_argument(args = ("-n", "--volume_name"), default = "", description = "Volume name written into every image; ignored when `-a` is given")
parser.add_boolean_argument(args = ("-a", "--auto_volume_name"), description = "Use each folder's name, or each zip's name without its extension, as its volume name")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete the source folders, or the zips and their extracted folders, once each image is made")
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

    # Create iso images from folders
    if args.disc_source_type == config.DiscSourceType.FOLDER:
        for obj in paths.get_directory_contents(input_path):
            obj_path = paths.join_paths(input_path, obj)
            if not paths.is_path_directory(obj_path):
                continue

            # Check if iso already exists
            output_file = paths.join_paths(input_path, obj + config.DiscImageFileType.ISO.cval())
            if os.path.exists(output_file):
                continue

            # Get volume name
            volume_name = args.volume_name
            if args.auto_volume_name:
                volume_name = obj

            # Create iso
            iso.create_iso(
                iso_file = output_file,
                source_dir = obj_path,
                volume_name = volume_name,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Create iso images from zips
    elif args.disc_source_type == config.DiscSourceType.ZIP:
        for file in paths.build_file_list_by_extensions(input_path, extensions = [".zip"]):

            # Get file info
            current_file = file
            current_dir = paths.get_filename_directory(current_file)
            current_basename = paths.get_filename_basename(current_file)

            # Check if iso already exists
            output_file = paths.join_paths(current_dir, current_basename + config.DiscImageFileType.ISO.cval())
            if os.path.exists(output_file):
                continue

            # Decompress zip
            extracted_dir = paths.join_paths(current_dir, current_basename + "_extracted")
            archive.extract_archive(
                archive_file = current_file,
                extract_dir = extracted_dir,
                work_dir = current_dir,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

            # Get volume name
            volume_name = args.volume_name
            if args.auto_volume_name:
                volume_name = current_basename

            # Create iso
            iso.create_iso(
                iso_file = output_file,
                source_dir = extracted_dir,
                volume_name = volume_name,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
