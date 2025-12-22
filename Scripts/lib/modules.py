# Imports
import sys

# Local imports
import system

###########################################################
# Python module importing
###########################################################

# Import python module package
def import_python_module_package(module_path, module_name):
    import importlib
    if system.IsPathDirectory(module_path):
        if module_name not in sys.modules:
            sys.path.append(module_path)
            module = importlib.import_module(module_name)
            return module
        else:
            return sys.modules[module_name]
    return None

# Import python module file
def import_python_module_file(module_path, module_name):
    import importlib.util
    if system.IsPathFile(module_path):
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return sys.modules[module_name]
    return None
