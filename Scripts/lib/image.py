# Imports
import os
import sys

# Local imports
import config
import system

# Detect if image is a certain format
def IsImageFormat(image_file, image_format):
    try:
        from PIL import Image
        with Image.open(image_file) as img:
            return img.format == image_format
    except:
        return False

# Detect if image is jpeg
def IsImageJPEG(image_file):
    return IsImageFormat(
        image_file = image_file,
        image_format = config.ImageType.JPEG)

# Detect if image is png
def IsImagePNG(image_file):
    return IsImageFormat(
        image_file = image_file,
        image_format = config.ImageType.PNG)

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
            system.Log("Converting image %s to %s" % (image_src, image_dest))
        if not pretend_run:
            from PIL import Image
            src_image = Image.open(image_src)
            rgb_image = src_image.convert("RGB")
            if not image_format:
                image_ext = system.GetFilenameExtension(image_dest).lower()
                if image_ext in config.image_extensions_jpeg:
                    image_format = config.ImageType.JPEG
                elif image_ext in config.image_extensions_png:
                    image_format = config.ImageType.PNG
            if not pretend_run:
                rgb_image.save(image_dest, image_format.camelcase)
            return system.DoesPathExist(image_dest)
        return False
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to convert %s to %s" % (image_src, image_dest))
            system.LogError(e)
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
        return system.TransferFile(
            src = image_src,
            dest = image_dest,
            skip_existing = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return ConvertImage(
        image_src = image_src,
        image_dest = image_dest,
        image_format = config.ImageType.JPEG,
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
        return system.TransferFile(
            src = image_src,
            dest = image_dest,
            skip_existing = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return ConvertImage(
        image_src = image_src,
        image_dest = image_dest,
        image_format = config.ImageType.PNG,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
