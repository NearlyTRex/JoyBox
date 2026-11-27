# Imports
import base64
import importlib

# Local imports
from joybox import config
from joybox import fileops
from joybox import filebulk
from joybox import serialization
from joybox import logger
from joybox import paths
from joybox import runtime

# Get PIL.Image, imported on first use
def _get_pil_image():
    return importlib.import_module("PIL.Image")

# Get image format
def get_image_format(image_file):
    if paths.is_path_file(image_file):
        pil_image = _get_pil_image()
        try:
            with pil_image.open(image_file) as img:
                return config.ImageFileType.from_string(img.format)
        except OSError:
            return None
    else:
        image_ext = paths.get_filename_extension(image_file).lower()
        if image_ext in [".jpg", ".jpeg"]:
            return config.ImageFileType.JPEG
        if image_ext in [".png"]:
            return config.ImageFileType.PNG
        return None

# Detect if image is a certain format
def is_image_format(image_file, image_format):
    return get_image_format(image_file) == image_format

# Detect if image is jpeg
def is_image_jpeg(image_file):
    return is_image_format(
        image_file = image_file,
        image_format = config.ImageFileType.JPEG)

# Detect if image is png
def is_image_png(image_file):
    return is_image_format(
        image_file = image_file,
        image_format = config.ImageFileType.PNG)

# Convert image
def convert_image(
    image_src,
    image_dest,
    image_format = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    pil_image = _get_pil_image()
    try:
        if verbose:
            logger.log_info("Converting image %s to %s" % (image_src, image_dest))
        if not pretend_run:
            src_image = pil_image.open(image_src)
            if getattr(src_image, "is_animated", False):
                src_image.seek(0)
            rgb_image = src_image.convert("RGB")
            if not image_format:
                image_ext = paths.get_filename_extension(image_dest).lower()
                if image_ext in [".jpg", ".jpeg"]:
                    image_format = config.ImageFileType.JPEG
                elif image_ext in [".png"]:
                    image_format = config.ImageFileType.PNG
            if not image_format:
                if exit_on_failure:
                    logger.log_error("Unable to tell which image format to convert %s to" % image_dest)
                return False
            rgb_image.save(image_dest, image_format.val())
            return paths.does_path_exist(image_dest)
        return False
    except (OSError, ValueError) as e:
        if exit_on_failure:
            logger.log_error("Unable to convert %s to %s" % (image_src, image_dest))
            logger.log_error(e)
            runtime.quit_program()
        return False

# Convert image to jpeg
def convert_image_to_jpeg(
    image_src,
    image_dest,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if is_image_jpeg(image_src):
        return filebulk.smart_transfer(
            src = image_src,
            dest = image_dest,
            skip_existing = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return convert_image(
        image_src = image_src,
        image_dest = image_dest,
        image_format = config.ImageFileType.JPEG,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Convert image to png
def convert_image_to_png(
    image_src,
    image_dest,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if is_image_png(image_src):
        return filebulk.smart_transfer(
            src = image_src,
            dest = image_dest,
            skip_existing = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return convert_image(
        image_src = image_src,
        image_dest = image_dest,
        image_format = config.ImageFileType.PNG,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Convert image data to format and return base64 string
def convert_image_data_to_format(
    image_data,
    target_format,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary files for conversion
    temp_input_ok, temp_input = fileops.create_temporary_file(suffix=".tmp")
    temp_output_ok, temp_output = fileops.create_temporary_file(suffix=target_format.cval())
    if not temp_input_ok or not temp_output_ok:
        logger.log_error("Failed to create temporary file")
        for created_ok, created_file in [(temp_input_ok, temp_input), (temp_output_ok, temp_output)]:
            if created_ok:
                fileops.remove_file(created_file)
        return None

    # Write original image data to temp file, then convert it to the target format
    if serialization.write_binary_file(temp_input, image_data) and convert_image(
        image_src = temp_input,
        image_dest = temp_output,
        image_format = target_format,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure):

        # Read converted image data
        converted_data = serialization.read_binary_file(temp_output)

        # Clean up temp files
        fileops.remove_file(temp_input)
        fileops.remove_file(temp_output)

        # Return base64 encoded data
        return base64.b64encode(converted_data).decode("utf-8") if converted_data is not None else None

    # Clean up temp files on failure
    fileops.remove_file(temp_input)
    fileops.remove_file(temp_output)
    return None
