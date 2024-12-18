#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import setup
import nintendo

# Parse arguments
parser = argparse.ArgumentParser(description="Nintendo 3DS rom tool.")
parser.add_argument("path", help="Input path")
parser.add_argument("-a", "--cia_to_cci", action="store_true", help="Convert CIA to 3DS(CCI)")
parser.add_argument("-b", "--cci_to_cia", action="store_true", help="Convert 3DS(CCI) to CIA")
parser.add_argument("-t", "--trim_cci", action="store_true", help="Trim 3DS(CCI) files")
parser.add_argument("-u", "--untrim_cci", action="store_true", help="Untrim 3DS(CCI) files")
parser.add_argument("-e", "--extract_cia", action="store_true", help="Extract CIA files")
parser.add_argument("-i", "--info", action="store_true", help="Print info for all 3DS files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    system.QuitProgram()

# Check input path
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.path)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Find rom files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".cia", ".3ds"]):
        current_file = file
        current_file_dir = system.GetFilenameDirectory(current_file)
        current_file_basename = system.GetFilenameBasename(current_file).replace(".trim", "")
        current_file_ext = system.GetFilenameExtension(current_file)
        output_file_cia = os.path.join(current_file_dir, current_file_basename + ".cia")
        output_file_3ds = os.path.join(current_file_dir, current_file_basename + ".3ds")
        output_file_trimmed_3ds = os.path.join(current_file_dir, current_file_basename + ".trim.3ds")
        output_dir = os.path.join(current_file_dir, current_file_basename)

        # Convert CIA to 3DS(CCI)
        if args.cia_to_cci and current_file.endswith(".cia"):
            nintendo.Convert3DSCIAtoCCI(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_trimmed_3ds,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Convert 3DS(CCI) to CIA
        elif args.cci_to_cia and current_file.endswith(".3ds"):
            nintendo.Convert3DSCCItoCIA(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_cia,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Trim 3DS
        elif args.trim_cci and current_file.endswith(".3ds") and not ".trim" in current_file:
            nintendo.Trim3DSCCI(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_trimmed_3ds,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Untrim 3DS
        elif args.untrim_cci and current_file.endswith(".trim.3ds"):
            nintendo.Untrim3DSCCI(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_3ds,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Extract CIA
        elif args.extract_cia and current_file.endswith(".cia"):
            nintendo.Extract3DSCIA(
                src_3ds_file = current_file,
                extract_dir = output_dir,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Print info
        elif args.info:
            info = nintendo.Get3DSFileInfo(
                src_3ds_file = current_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            system.Log(info)

# Start
main()
