# Local imports
from joybox import command
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import serialization

# Write content to a new temporary file; its path, or None (logged) when it can't be created
def _write_temporary_content(content, suffix, prefix, verbose, pretend_run, exit_on_failure):

    # Create temp file
    temp_path_ok, temp_path = fileops.create_temporary_file(
        suffix = suffix,
        prefix = prefix,
        verbose = verbose,
        pretend_run = pretend_run)
    if not temp_path_ok:
        logger.log_error("Failed to create temporary file")
        return None

    # Write text content
    serialization.write_text_file(
        src = temp_path,
        contents = content,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return temp_path

# Remove the editor's temporary file, never exiting on failure
def _remove_temporary_file(temp_path, verbose, pretend_run):
    fileops.remove_file(
        src = temp_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = False)

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

    # Create temp file with the content
    temp_path = _write_temporary_content(content, suffix, prefix, verbose, pretend_run, exit_on_failure)
    if temp_path is None:
        return None

    # Open editor
    success = command.run_interactive_command(
        cmd = [editor, temp_path],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Failed to open editor '%s'" % editor)
        _remove_temporary_file(temp_path, verbose, pretend_run)
        return None

    # Read result
    result = serialization.read_text_file(
        src = temp_path,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Cleanup
    _remove_temporary_file(temp_path, verbose, pretend_run)

    return result

# Parse a line-based action file, one "ACTION path [-> dest]" per line,
# skipping blank lines and # comments
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
