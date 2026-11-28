# Imports
import importlib
import importlib.util
import sys

# Local imports
from joybox import paths

###########################################################
# Python module importing
###########################################################

# Add module_path to sys.path and import module_name, reusing an already loaded one; None when the directory is missing
def import_python_module_package(module_path, module_name):
    if paths.is_path_directory(module_path):
        if module_name not in sys.modules:
            sys.path.append(module_path)
            module = importlib.import_module(module_name)
            return module
        return sys.modules[module_name]
    return None

# Load a single .py file as module_name and register it in sys.modules; None when the file is missing
def import_python_module_file(module_path, module_name):
    if paths.is_path_file(module_path):
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return sys.modules[module_name]
    return None
