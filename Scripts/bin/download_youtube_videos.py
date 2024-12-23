#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import metadata
import youtube
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Download youtube videos.")
parser.add_argument("youtube_url", help="YouTube url")
parser.add_argument("-o", "--output_file", help="Output file")
parser.add_argument("-d", "--output_dir", type=str, default=os.path.realpath("."), help="Output dir")
parser.add_argument("-c", "--cookie_source", type=str, default="firefox", help="Cookie source")
parser.add_argument("-s", "--sanitize_filenames", action="store_true", help="Sanitize filenames")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Download videos
    youtube.DownloadVideo(
        video_url = args.youtube_url,
        output_file = args.output_file,
        output_dir = args.output_dir,
        cookie_source = args.cookie_source,
        sanitize_filenames = args.sanitize_filenames,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
main()
