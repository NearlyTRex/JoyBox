# Interactive user input prompts.
#
# Warnings on invalid input go through the stdlib logging module (logger name
# "joybox.userinput"), so they surface under whatever logging both trees have
# already configured, without this module depending on either tree's logger.

# Imports
import os
import logging

_log = logging.getLogger("joybox.userinput")

# Prompt for a value, returning the default when nothing is entered
def prompt_for_value(description, default_value = None):
    prompt = ">>> %s: " % (description)
    if default_value:
        prompt = ">>> %s [default: %s]: " % (description, default_value)
    value = input(prompt)
    if len(value) == 0:
        return default_value
    return value

# Prompt for an integer value
def prompt_for_int(description, default_value = None):
    while True:
        value = prompt_for_value(description, default_value)
        try:
            return int(value)
        except (TypeError, ValueError):
            _log.warning("Entered value '%s' was not a valid integer, please try again" % value)

# Alias matching the Scripts naming
prompt_for_integer_value = prompt_for_int

# Prompt for a value constrained to a set of choices
def prompt_for_choice(description, choices = [], default_value = None):
    while True:
        value = prompt_for_value(description, default_value)
        if not isinstance(value, str):
            continue
        if value.strip().lower() in choices:
            return value
        _log.warning("Entered value '%s' was not a valid choice, please try again" % value)

# Prompt for an existing file path
def prompt_for_file(description, default_value = None):
    while True:
        value = prompt_for_value(description, default_value)
        if not isinstance(value, str):
            continue
        if os.path.exists(os.path.realpath(value)):
            return value
        _log.warning("Entered value '%s' was not a valid file, please try again" % value)

# Prompt for a yes/no confirmation
def prompt_for_confirmation(description, default_yes = False):
    prompt_suffix = "[Y/n]" if default_yes else "[y/N]"
    while True:
        value = input(">>> %s %s: " % (description, prompt_suffix)).strip().lower()
        if value == "":
            return default_yes
        if value in ("y", "yes"):
            return True
        if value in ("n", "no"):
            return False
        _log.warning("Please enter 'y' or 'n'")
