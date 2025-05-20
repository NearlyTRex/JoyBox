# Imports
import os
import sys

# Local imports
import config
import system
import command
import programs

# Format C/C++ file
def FormatCppFile(
    src,
    style_name = None,
    style_inline = None,
    style_file = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get format command
    format_cmd = [
        "clang-format"
    ]
    if style_name:
        format_cmd += ["-style", style_name]
    elif style_inline:
        format_cmd += [f"-style=\"{style_inline}\""]
    elif style_file:
        format_cmd += ["-style", os.path.realpath(style_file)]
    format_cmd += [
        "-i", src
    ]

    # Run format command
    code = command.RunReturncodeCommand(
        cmd = format_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0
