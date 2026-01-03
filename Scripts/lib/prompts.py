# Local imports
import network
import logger
import serialization

###########################################################
# List summarization utilities
###########################################################

# Get summarized list of items
def get_summarized_list(items, max_display = 20):
    total_count = len(items)
    if total_count <= max_display:
        return list(items), total_count, False
    show_count = max_display // 2
    hidden_count = total_count - max_display
    summarized = list(items[:show_count])
    summarized.append("... (%d more items) ..." % hidden_count)
    summarized.extend(items[-show_count:])
    return summarized, total_count, True

# Write list summary
def write_list_summary(
    items,
    title = None,
    max_display = 20,
    indent = "  ",
    report_file = None,
    verbose = False,
    pretend_run = False):

    # Log title if provided
    if title:
        logger.log_info(title)

    # Get summarized list and log items
    summarized, total_count, _ = get_summarized_list(items, max_display)
    if total_count == 0:
        logger.log_info("%s(none)" % indent)
    else:
        for item in summarized:
            logger.log_info("%s%s" % (indent, item))

    # Log total
    logger.log_info("Total: %d items" % total_count)

    # Write full list to file if requested
    if report_file and total_count > 0:
        report_content = "\n".join(str(item) for item in items)
        success = serialization.write_text_file(
            src = report_file,
            contents = report_content,
            verbose = verbose,
            pretend_run = pretend_run)
        if success:
            logger.log_info("Full list written to: %s" % report_file)
        else:
            logger.log_error("Failed to write report file: %s" % report_file)
        return success
    return True

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
        summarized, total_count, _ = get_summarized_list(details, max_details)
        for detail in summarized:
            logger.log_info("  %s" % detail)
        logger.log_info("-" * 60)
        logger.log_info("Total items: %d" % total_count)
    logger.log_info("=" * 60)
    return prompt_for_confirmation("Proceed?", default_yes = default_yes)
