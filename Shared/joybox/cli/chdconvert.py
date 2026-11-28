# Imports
from joybox import config
from joybox import system
from joybox import chd
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "chdconvert")
    parser.add_input_path_argument(description = "A disc image file, or a directory searched recursively for images; must exist")
    parser.add_enum_argument(
        args = ("-t", "--disc_image_types"),
        arg_type = config.DiscImageFileType,
        default = [config.DiscImageFileType.ISO, config.DiscImageFileType.CUE, config.DiscImageFileType.GDI, config.DiscImageFileType.TOAST, config.DiscImageFileType.MDS],
        description = "Image types to convert, space separated; each selects files by its extension (`ISO` is `.iso`, `CUE` is `.cue`, and so on)",
        allow_multiple = True)
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete the image file given to chdman (the `.iso`, `.cue`, `.gdi`, `.toc` or `.toast` itself, or an `.mds` together with its `.mdf`) once its CHD is made")
    parser.add_common_arguments()
    return parser

# After a preview, convert each CD image of the chosen types under the input to a CHD beside it, skipping those already converted
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    details = [
        "Path: %s" % input_path,
        "Disc image types: %s" % [t.cval() for t in args.disc_image_types],
        "Delete originals: %s" % args.delete_originals
    ]
    if not prompts.confirm_preview(args.no_preview, "Convert to CHD", details):
        return

    # Convert disc image files
    chd.convert_disc_images_to_chd(
        input_path = input_path,
        disc_image_types = args.disc_image_types,
        delete_originals = args.delete_originals,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
