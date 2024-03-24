# Imports
import os
import sys

###########################################################
# Logging
###########################################################

# Log message
def Log(message):
    print(message)

###########################################################
# Prompts
###########################################################

# Prompt for value
def PromptForValue(description, default_value = None):
    prompt = ">>> %s: " % (description)
    if default_value:
        prompt = ">>> %s [default: %s]: " % (description, default_value)
    value = input(prompt)
    if len(value) == 0:
        return default_value
    return value
