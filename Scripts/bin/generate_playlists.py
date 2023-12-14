#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import music
import system
import setup
import ini

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Paths
    music_base_dir = environment.GetSyncedMusicRootDir()

    # Make music playlists
    for obj in system.GetDirectoryContents(music_base_dir):
        obj_path = os.path.join(music_base_dir, obj)
        if os.path.isdir(obj_path):
            music.GenerateMusicPlaylist(
                source_dir = obj_path,
                output_file = os.path.join(music_base_dir, obj + ".m3u"),
                verbose = verbose)

# Start
main()
