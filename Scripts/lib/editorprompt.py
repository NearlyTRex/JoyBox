# Imports
import os, os.path
import sys

# Local imports
import command
import environment
import fileops
import logger
import serialization

# Open editor for user to review and modify content
def open_editor(
    content,
    suffix = ".txt",
    prefix = "editor_",
    editor = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Determine editor
    if not editor:
        editor = environment.get_editor()

    # Create temp file
    temp_path = fileops.create_temporary_file(
        suffix = suffix,
        prefix = prefix,
        verbose = verbose,
        pretend_run = pretend_run)
    if not temp_path:
        logger.log_error("Failed to create temporary file")
        return None

    # Write text content
    serialization.write_text_file(
        src = temp_path,
        contents = content,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Open editor
    success = command.run_interactive_command(
        cmd = [editor, temp_path],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Failed to open editor '%s'" % editor)
        fileops.remove_file(
            src = temp_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        return None

    # Read result
    result = serialization.read_text_file(
        src = temp_path,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Cleanup
    fileops.remove_file(
        src = temp_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = False)

    return result

# Parse a line-based action file where:
# - Lines starting with # are comments (ignored)
# - Empty lines are ignored
# - Each line is: ACTION path [-> dest]
def parse_action_lines(
    content,
    comment_char = "#",
    arrow_separator = " -> "):

    # Build actions
    actions = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(comment_char):
            continue

        # Parse: ACTION path [-> dest_name]
        parts = line.split(maxsplit=1)
        if len(parts) < 2:
            continue
        action_type = parts[0].upper()
        path_part = parts[1]

        # Handle arrow separator for src -> dest patterns
        if arrow_separator in path_part:
            src, dest = path_part.split(arrow_separator, 1)
            actions.append({
                'type': action_type,
                'src': src.strip(),
                'dest': dest.strip()
            })
        else:
            actions.append({
                'type': action_type,
                'path': path_part.strip()
            })
    return actions

# Open editor for action-based prompts
def open_editor_for_actions(
    content,
    suffix = ".txt",
    prefix = "actions_",
    editor = None,
    comment_char = "#",
    arrow_separator = " -> ",
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    result = open_editor(
        content = content,
        suffix = suffix,
        prefix = prefix,
        editor = editor,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if result is None:
        return None
    return parse_action_lines(
        content = result,
        comment_char = comment_char,
        arrow_separator = arrow_separator)

# Generate a standard action file with sections
def generate_action_file(
    sections,
    header_lines = None,
    comment_char = "#"):

    # Add header lines
    lines = []
    if header_lines:
        for header in header_lines:
            lines.append("%s %s" % (comment_char, header))
        lines.append("")

    # Add each section
    for section in sections:
        section_title = section.get("title", "")
        section_items = section.get("items", [])
        commented = section.get("commented", False)
        description = section.get("description", None)
        if not section_items:
            continue

        # Section header
        lines.append("%s === %s ===" % (comment_char, section_title))
        if description:
            lines.append("%s %s" % (comment_char, description))

        # Section items
        for item in section_items:
            line = item
            if commented:
                line = "%s%s" % (comment_char, line)
            lines.append(line)
        lines.append("")
    return "\n".join(lines)
