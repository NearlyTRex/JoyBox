# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import command
import environment

# Install windows system package
def InstallWindowsSystemPackage(package, verbose = False, exit_on_failure = False):
    pass

# Install linux system package
def InstallLinuxSystemPackage(package, verbose = False, exit_on_failure = False):

    # Get install command
    install_cmd = [
        "sudo",
        "apt",
        "-y",
        "install",
        "--no-install-recommends",
        package
    ]

    # Run install command
    code = command.RunBlockingCommand(
        cmd = install_cmd,
        options = command.CommandOptions(
            allow_processing = False),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return (code == 0)

# Install system package
def InstallSystemPackage(package, verbose = False, exit_on_failure = False):
    if environment.IsWindowsPlatform():
        InstallWindowsSystemPackage(
            package = package,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
    elif environment.IsLinuxPlatform():
        InstallLinuxSystemPackage(
            package = package,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
