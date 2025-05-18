#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import decompiler
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Decompiler tool.")
parser.add_string_argument(args = ("-n", "--project_name"), description = "Project name")
parser.add_string_argument(args = ("-l", "--project_language"), default = "x86:LE:32:watcom", description = "Project language")
parser.add_string_argument(args = ("-c", "--project_cspec"), default = "watcomcpp", description = "Project compiler spec")
parser.add_input_path_argument(args = ("-r", "--project_dir"), description = "Project directory")
parser.add_input_path_argument(args = ("-i", "--program_binary_file"), description = "Program binary file")
parser.add_string_argument(args = ("-a", "--program_name"), description = "Program name")
parser.add_output_path_argument(args = ("-o", "--export_dir"), description = "Export directory")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Create project options
    project_options = decompiler.ProjectOptions(
        project_name = args.project_name,
        project_dir = args.project_dir,
        project_language = args.project_language,
        project_cspec = args.project_cspec,
        program_name = args.program_name,
        program_binary_file = args.program_binary_file)

    # Open project
    with decompiler.DecompilerProject(project_options) as project:
        project.ExportFunctions(
            export_dir = args.export_dir,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
main()
