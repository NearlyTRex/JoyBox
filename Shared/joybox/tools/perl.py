# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Perl tool
class Perl(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Perl"

    # Get config
    def get_config(self):

        # Get perl info
        perl_exe = settings.get_value("Tools.Perl", "perl_exe")
        perl_install_dir = settings.get_path_value("Tools.Perl", "perl_install_dir")

        # Return config
        return {

            # Perl
            "Perl": {
                "program": paths.join_paths(perl_install_dir, perl_exe)
            }
        }
