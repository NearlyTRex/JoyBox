#!/usr/bin/env python3

# Imports
import os
import os.path
import sys
import argparse
import mergedeep
import dictdiffer

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import system
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Compare hash files against a reference file.")
parser.add_argument("-h", "--reference_hash_file", help="Reference hash file")
parser.add_argument("-d", "--testing_hash_dir", help="Testing hash file directory")
args, unknown = parser.parse_known_args()

# Check reference file path
reference_hash_file = os.path.realpath(args.reference_hash_file)
if not os.path.exists(reference_hash_file):
    print("Reference file '%s' does not exist" % args.reference_hash_file)
    sys.exit(-1)

# Check testing hash file directory
testing_hash_dir = os.path.realpath(args.testing_hash_dir)
if not os.path.exists(testing_hash_dir):
    print("Testing directory '%s' does not exist" % args.testing_hash_dir)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Read hash file
    def ReadHashFile(filename):
        hash_contents = {}
        with open(filename, "r", encoding="utf8") as f:
            for line in f.readlines():
                for token in line.strip().split(" || "):
                    file_location = token[0]
                    file_crc32 = token[1]
                    file_size = token[2]
                    file_entry = {}
                    file_entry["crc32"] = file_crc32
                    file_entry["size"] = file_size
                    hash_contents[file_location] = file_entry
        return hash_contents

    # Read reference file
    reference_hash_database = ReadHashFile(reference_hash_file)

    # Read testing files
    testing_hash_database = {}
    for file in system.BuildFileListByExtensions(input_path, extensions = [".txt"]):
        testing_hash_database = mergedeep.merge(testing_hash_database, ReadHashFile(file))

# Start
environment.RunAsRootIfNecessary(main)
