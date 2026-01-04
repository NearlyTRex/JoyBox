# Imports
import os
import sys

# Local imports
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

# Write list report
def write_list_report(
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
