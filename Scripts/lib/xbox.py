# Imports
import os
import os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import command
import programs
import system
import environment

# Extract Xbox ISO
def ExtractXboxISO(iso_file, extract_dir, delete_original = False, verbose = False, exit_on_failure = False):

    # Get extract command
    extract_cmd = [
        programs.GetToolProgram("ExtractXIso"),
        "-x",
        "-d", extract_dir,
        iso_file
    ]

    # Run extract command
    try:
        command.RunExceptionCommand(
            cmd = extract_cmd,
            options = command.CommandOptions(
                allow_processing = environment.IsWinePlatform()),
            verbose = verbose)
    except:
        if exit_on_failure:
            print("Unable to extract xbox iso '%s' to '%s'" % (iso_file, extract_dir))
            sys.exit(1)
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(iso_file)

    # Check result
    return os.path.exists(extract_dir)

# Rewrite Xbox ISO
def RewriteXboxISO(iso_file, delete_original = False, verbose = False, exit_on_failure = False):

    # Get rewrite command
    rewrite_cmd = [
        programs.GetToolProgram("ExtractXIso"),
        "-r",
        "-d", system.GetFilenameDirectory(iso_file)
    ]
    if delete_original:
        rewrite_cmd += ["-D"]
    rewrite_cmd += [system.GetFilenameFile(iso_file)]

    # Run rewrite command
    try:
        command.RunExceptionCommand(
            cmd = rewrite_cmd,
            options = command.CommandOptions(
                cwd = system.GetFilenameDirectory(iso_file),
                allow_processing = environment.IsWinePlatform()),
            verbose = verbose)
    except:
        if exit_on_failure:
            print("Unable to rewrite xbox iso '%s'" % iso_file)
            sys.exit(1)
        return False

    # Must have worked
    return True
