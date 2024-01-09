# Imports
import os
import sys

# Prompt for value
def PromptForValue(description, default_value):
    value = input(">>> %s [default: %s]: " % (description, default_value))
    if len(value) == 0:
        return default_value
    return value
