# Program control and time helpers.

# Imports
import os
import sys
import time

###########################################################
# Program control
###########################################################

# Exit the process with the given code, -1 by default
def quit_program(exit_code = -1):
    sys.exit(exit_code)

# Block the current thread for the given number of seconds
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

# The user's home directory, expanded from ~
def get_home_directory():
    return os.path.expanduser("~")

# Where saved browser cookies live: Cookies under the home directory
def get_cookie_directory():
    return os.path.join(get_home_directory(), "Cookies")

# Where logs live: Logs under the home directory
def get_log_directory():
    return os.path.join(get_home_directory(), "Logs")
