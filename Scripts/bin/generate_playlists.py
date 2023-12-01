#!/usr/bin/env python3

# Imports
import os
import os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import music
import system
import setup

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Paths
    music_base_dir = environment.GetSyncedMusicRootDir()

    # Make music playlists
    for obj in system.GetDirectoryContents(music_base_dir):
        obj_path = os.path.join(music_base_dir, obj)
        if os.path.isdir(obj_path):
            music.GenerateMusicPlaylist(
                source_dir = obj_path,
                output_file = os.path.join(music_base_dir, obj + ".m3u"),
                verbose = True)

# Start
environment.RunAsRootIfNecessary(main)
