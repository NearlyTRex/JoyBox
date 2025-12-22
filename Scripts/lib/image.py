# Imports
import os
import sys
import base64

# Local imports
import config
import fileops
import system
import logger
import paths

# Get image format
def GetImageFormat(image_file):
    if paths.is_path_file(image_file):
        try:
            from PIL import Image
            with Image.open(image_file) as img:
                return config.ImageFileType.from_string(img.format)
        except:
            return None
    else:
        image_ext = paths.get_filename_extension(image_file).lower()
        if image_ext in [".jpg", ".jpeg"]:
            return config.ImageFileType.JPEG
        if image_ext in [".png"]:
            return config.ImageFileType.PNG
        return None

# Detect if image is a certain format
def IsImageFormat(image_file, image_format):
    return (GetImageFormat(image_file) == image_format)

# Detect if image is jpeg
def IsImageJPEG(image_file):
    return IsImageFormat(
        image_file = image_file,
        image_format = config.ImageFileType.JPEG)

# Detect if image is png
def IsImagePNG(image_file):
    return IsImageFormat(
        image_file = image_file,
        image_format = config.ImageFileType.PNG)

# Convert image
def ConvertImage(
    image_src,
    image_dest,
    image_format = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Converting image %s to %s" % (image_src, image_dest))
        if not pretend_run:
            from PIL import Image
            src_image = Image.open(image_src)
            if src_image.is_animated:
                src_image.seek(0)
            rgb_image = src_image.convert("RGB")
            if not image_format:
                image_ext = paths.get_filename_extension(image_dest).lower()
                if image_ext in [".jpg", ".jpeg"]:
                    image_format = config.ImageFileType.JPEG
                elif image_ext in [".png"]:
                    image_format = config.ImageFileType.PNG
            if not pretend_run:
                rgb_image.save(image_dest, image_format.val())
            return paths.does_path_exist(image_dest)
        return False
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to convert %s to %s" % (image_src, image_dest))
            logger.log_error(e)
            system.QuitProgram()
        return False

# Convert image to jpeg
def ConvertImageToJPEG(
    image_src,
    image_dest,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if IsImageJPEG(image_src):
        return fileops.smart_transfer(
            src = image_src,
            dest = image_dest,
            skip_existing = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return ConvertImage(
        image_src = image_src,
        image_dest = image_dest,
        image_format = config.ImageFileType.JPEG,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Convert image to png
def ConvertImageToPNG(
    image_src,
    image_dest,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if IsImagePNG(image_src):
        return fileops.smart_transfer(
            src = image_src,
            dest = image_dest,
            skip_existing = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return ConvertImage(
        image_src = image_src,
        image_dest = image_dest,
        image_format = config.ImageFileType.PNG,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Convert image data to format and return base64 string
def ConvertImageDataToFormat(
    image_data,
    target_format,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary files for conversion
    temp_input = fileops.create_temporary_file(suffix=".tmp")
    temp_output = fileops.create_temporary_file(suffix=target_format.cval())

    # Write original image data to temp file
    with open(temp_input, "wb") as f:
        f.write(image_data)

    # Convert to target format
    if ConvertImage(
        image_src = temp_input,
        image_dest = temp_output,
        image_format = target_format,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure):

        # Read converted image data
        with open(temp_output, "rb") as f:
            converted_data = f.read()

        # Clean up temp files
        fileops.remove_file(temp_input)
        fileops.remove_file(temp_output)

        # Return base64 encoded data
        return base64.b64encode(converted_data).decode("utf-8")

    # Clean up temp files on failure
    fileops.remove_file(temp_input)
    fileops.remove_file(temp_output)
    return None
