# Nintendo Wii WAD files: installing them into an emulated NAND.

# Imports

# Local imports
from joybox import fileops
from joybox import logger
from joybox import serialization

# Install Wii WAD file into an emulated NAND
def install_wii_wad(
    src_wad_file,
    nand_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    import libWiiPy

    # Read wad
    wad_data = serialization.read_binary_file(
        src = src_wad_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if wad_data is None:
        logger.log_error("Unable to read WAD %s" % src_wad_file)
        return False

    # Load title
    try:
        title = libWiiPy.title.Title()
        title.load_wad(wad_data)
    except Exception as e:
        logger.log_error("Unable to load WAD %s" % src_wad_file)
        logger.log_error(e, quit_program = exit_on_failure)
        return False

    # Make nand directory
    success = fileops.make_directory(
        src = nand_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Install title
    if verbose:
        logger.log_info("Installing %s into NAND %s" % (src_wad_file, nand_dir))
    if pretend_run:
        return True
    try:
        libWiiPy.nand.EmuNAND(nand_dir).install_title(title)
    except Exception as e:
        logger.log_error("Unable to install WAD %s" % src_wad_file)
        logger.log_error(e, quit_program = exit_on_failure)
        return False
    return True

######################################################
