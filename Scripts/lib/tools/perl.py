# Imports
import os, os.path
import sys

# Local imports
import system
import toolbase
import ini

# Config files
config_files = {}

# Perl tool
class Perl(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Perl"

    # Get config
    def GetConfig(self):

        # Get perl info
        perl_exe = ini.GetIniValue("Tools.Perl", "perl_exe")
        perl_install_dir = ini.GetIniPathValue("Tools.Perl", "perl_install_dir")

        # Return config
        return {

            # Perl
            "Perl": {
                "program": system.JoinPaths(perl_install_dir, perl_exe)
            }
        }
