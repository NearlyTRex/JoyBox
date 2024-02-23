#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import steam
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Download Steam game.")
parser.add_argument("appid", help="App id to download")
parser.add_argument("-b", "--branchid", type=str, help="Branch id to download")
parser.add_argument("-l", "--login", type=str, help="Steam login username")
parser.add_argument("-p", "--platform",
    choices=[
        "windows",
        "linux"
    ],
    default="windows",
    help="Download platform"
)
parser.add_argument("-a", "--arch",
    choices=[
        "32",
        "64"
    ],
    default="64",
    help="Download architecture"
)
parser.add_argument("-o", "--output_dir", type=str, default=".", help="Output directory for downloads")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Download game
    steam.DownloadGame(
        appid = args.appid,
        branchid = args.branchid,
        output_dir = args.output_dir,
        platform = args.platform,
        arch = args.arch,
        login = args.login,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Start
main()
