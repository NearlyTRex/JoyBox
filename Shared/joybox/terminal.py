# Imports
import os
import sys

###########################################################
# Colour
###########################################################

# Terminal colour for interactive scripts. The logger colours its own
# output; this is for everything a script prints directly, such as a prompt
# or streamed model output.

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
RED = "\033[31;1m"
GREEN = "\033[32;1m"
YELLOW = "\033[33m"
BLUE = "\033[34;1m"
CYAN = "\033[36;1m"

# Colour only when attached to a terminal and not asked to stop
def supports_colour(stream = None):
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()

# Wrap text in a colour, or return it unchanged when colour is off
def paint(text, code, stream = None):
    if not supports_colour(stream):
        return text
    return f"{code}{text}{RESET}"

###########################################################
# Output
###########################################################

# Write without buffering, for streamed output that should appear as it
# arrives rather than at the end of a line
def write(text):
    sys.stdout.write(text)
    sys.stdout.flush()

# Print a dimmed status line
def status(message):
    print(paint(f"  {message}", DIM))

# Print a warning without going through the logger, for interactive use
# where a timestamped log line would be noise
def notice(message):
    print(paint(f"  {message}", YELLOW))

###########################################################
# Input
###########################################################

# Read a line with editing and history enabled. Returns None at EOF or on
# interrupt, so a caller can treat both as "done".
def read_line(prompt_text, colour = CYAN):
    try:
        import readline  # noqa: F401  -- enables editing and history
    except ImportError:
        pass
    try:
        return input(paint(prompt_text, colour))
    except (EOFError, KeyboardInterrupt):
        print()
        return None
