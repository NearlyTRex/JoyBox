# Local imports
import network
import logger

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
        if network.IsUrlReachable(value):
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
        total_count = len(details)
        if total_count <= max_details:
            for detail in details:
                logger.log_info("  %s" % detail)
        else:
            show_count = max_details // 2
            for detail in details[:show_count]:
                logger.log_info("  %s" % detail)
            logger.log_info("  ... (%d more items) ..." % (total_count - max_details))
            for detail in details[-show_count:]:
                logger.log_info("  %s" % detail)
        logger.log_info("-" * 60)
        logger.log_info("Total items: %d" % total_count)
    logger.log_info("=" * 60)
    return prompt_for_confirmation("Proceed?", default_yes = default_yes)
