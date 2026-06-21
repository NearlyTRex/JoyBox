# Local imports
import joybox.paths as paths
import joybox.toolbase as toolbase
import joybox.settings as settings

# Config files
config_files = {}

# Python tool
class Python(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Python"

    # Get config
    def get_config(self):

        # Get python info
        python_exe = settings.get_value("Tools.Python", "python_exe")
        python_pip_exe = settings.get_value("Tools.Python", "python_pip_exe")
        python_install_dir = settings.get_path_value("Tools.Python", "python_install_dir")
        python_venv_dir = settings.get_path_value("Tools.Python", "python_venv_dir")

        # Return config
        return {

            # Python
            "Python": {
                "program": paths.join_paths(python_install_dir, python_exe),
                "venv_dir": python_venv_dir
            },

            # PythonVenvPython
            "PythonVenvPython": {
                "program": {
                    "windows": paths.join_paths(python_venv_dir, "Scripts", python_exe),
                    "linux": paths.join_paths(python_venv_dir, "bin", python_exe)
                }
            },

            # PythonVenvPip
            "PythonVenvPip": {
                "program": {
                    "windows": paths.join_paths(python_venv_dir, "Scripts", python_pip_exe),
                    "linux": paths.join_paths(python_venv_dir, "bin", python_pip_exe)
                }
            }
        }
