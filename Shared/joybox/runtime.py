# Program control and time helpers.

# Imports
import os
import sys
import time

###########################################################
# Program control
###########################################################

# Quit program
def quit_program(exit_code = -1):
    sys.exit(exit_code)

# Sleep program
def sleep_program(seconds):
    time.sleep(seconds)

###########################################################
# Time
###########################################################

# Get current time (float seconds since the epoch)
def get_current_time():
    return time.time()

# Get current timestamp (integer seconds since the epoch)
def get_current_timestamp():
    return int(time.time())

###########################################################
# Directories
###########################################################

# Get home directory
def get_home_directory():
    return os.path.expanduser("~")

# Get cookie directory
def get_cookie_directory():
    return os.path.join(get_home_directory(), "Cookies")

# Get log directory
def get_log_directory():
    return os.path.join(get_home_directory(), "Logs")
