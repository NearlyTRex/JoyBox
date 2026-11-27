# Local imports
from joybox import paths
from joybox import programs
from joybox import toolbase


# Files under the VKD3D lib dir whose names end with an entry of the given tool config list
def get_libs(key):
    lib_files = []
    lib_root = programs.get_library_install_dir("VKD3D", "lib")
    for potential_file in paths.build_file_list(lib_root):
        for lib_file in programs.get_tool_config_value("VKD3D", key):
            if potential_file.endswith(lib_file):
                lib_files.append(potential_file)
    return lib_files

# Get 32-bit libs
def get_libs32():
    return get_libs("lib32")

# Get 64-bit libs
def get_libs64():
    return get_libs("lib64")

# VKD3D tool
class VKD3D(toolbase.ToolBase):

    NAME = "VKD3D"
