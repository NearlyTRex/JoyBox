# Imports
import os
import sys

# Local imports
import network
import logger
import reports

###########################################################
# User input and prompt utilities
###########################################################

# Prompt for value
def prompt_for_value(description, default_value = None):
    prompt = ">>> %s: " % (description)
    if default_value:
        prompt = ">>> %s [default: %s]: " % (description, default_value)
    value = input(prompt)
    if len(value) == 0:
        return default_value
    return value

# Prompt for integer value
def prompt_for_integer_value(description, default_value = None):
    while True:
        value = prompt_for_value(description, default_value)
        try:
            return int(value)
        except:
            logger.log_warning("That was not a valid integer, please try again")

# Prompt for url
def prompt_for_url(description, default_value = None):
    while True:
        value = prompt_for_value(description, default_value)
        if network.is_url_reachable(value):
            return value
        logger.log_warning("That was not a valid url, please try again")

# Prompt for confirmation (y/n)
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
        logger.log_warning("Please enter 'y' or 'n'")

# Show preview and prompt for confirmation
def prompt_for_preview(operation, details = [], default_yes = True, max_details = 20):
    logger.log_info("=" * 60)
    logger.log_info("Operation: %s" % operation)
    if details:
        logger.log_info("-" * 60)
        summarized, total_count, _ = reports.get_summarized_list(details, max_details)
        for detail in summarized:
            logger.log_info("  %s" % detail)
        logger.log_info("-" * 60)
        logger.log_info("Total items: %d" % total_count)
    logger.log_info("=" * 60)
    return prompt_for_confirmation("Proceed?", default_yes = default_yes)

# Prompt for selection from a numbered list
def prompt_for_selection(description, options, display_func = None, allow_cancel = True):
    if not options:
        logger.log_warning("No options available")
        return None
    logger.log_info(description)
    logger.log_info("-" * 60)
    for i, option in enumerate(options):
        display = display_func(option) if display_func else str(option)
        logger.log_info("  %d) %s" % (i + 1, display))
    logger.log_info("-" * 60)
    if allow_cancel:
        logger.log_info("  0) Cancel")
    while True:
        value = prompt_for_value("Enter selection")
        try:
            index = int(value)
            if allow_cancel and index == 0:
                return None
            if 1 <= index <= len(options):
                return options[index - 1]
            logger.log_warning("Please enter a number between %d and %d" % (0 if allow_cancel else 1, len(options)))
        except (TypeError, ValueError):
            logger.log_warning("Please enter a valid number")
