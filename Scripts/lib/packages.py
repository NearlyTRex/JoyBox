# Imports
import os, os.path
import sys

# Local imports
import config
import command
import environment

# Get required system packages
def GetRequiredSystemPackages():
    required_packages = config.required_system_packages_all
    if environment.IsWindowsPlatform():
        required_packages += config.required_system_packages_windows
    elif environment.IsLinuxPlatform():
        required_packages += config.required_system_packages_linux
    return required_packages

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
