# Imports
import os

# Local imports
import environment

###########################################################
# Root access
###########################################################

# Determine if user is root
def is_user_root():
    if environment.IsWindowsPlatform():
        try:
            import pyuac
            return pyuac.isUserAdmin()
        except:
            return False
    else:
        return os.getuid() == 0

# Run as root
def run_as_root(func):
    if not callable(func):
        return
    if environment.IsWindowsPlatform():
        try:
            import pyuac
            if not pyuac.isUserAdmin():
                pyuac.runAsAdmin()
            else:
                func()
        except ModuleNotFoundError as e:
            func()
        except:
            raise
