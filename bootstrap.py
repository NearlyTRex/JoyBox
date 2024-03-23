#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
bootstrap_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "Bootstrap"))
sys.path.append(bootstrap_folder)
import system
import environment
import packages
import python
import ini

# Paths
ini_file = os.path.join(".", "JoyBox.ini")
scripts_bin_dir = os.path.join(os.path.dirname(__file__), "Scripts", "bin")
setup_tools_file = os.path.join(scripts_bin_dir, "setup_tools.py")

# Read ini values
ini_values = ini.OpenIniFile(ini_file)

# Setup packages
packages.Setup(ini_values)

# Setup python
python.Setup(ini_values)
python.RunScript(setup_tools_file, ini_values)

# Add to path
should_add_path = system.PromptForValue("Would you like to add %s to your PATH? (y/N)" % scripts_bin_dir, "N")
if should_add_path.lower() == "y":
    environment.AddToPath(scripts_bin_dir)

# Inform user
system.Log("Bootstrap complete!")
