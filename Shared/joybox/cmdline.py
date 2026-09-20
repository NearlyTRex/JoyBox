# Imports
import re
import copy
import shlex

# Flags whose following value should be masked when a command is logged.
SENSITIVE_FLAGS = [
    "--passphrase",
    "--password",
    "--token",
    "--secret",
]

###########################################################
# Command string
###########################################################

# Build a command string using POSIX shell quoting (correct for SSH / sh / bash).
def create_command_string_posix(cmd):
    if not cmd:
        return ""
    if len(cmd) == 0:
        return ""
    if isinstance(cmd, str):
        return copy.deepcopy(cmd)
    if isinstance(cmd, list):
        return " ".join(shlex.quote(cmd_segment) for cmd_segment in cmd)
    return ""

# Build a command string by wrapping only space-containing segments in quotes.
# Safe across platforms (including the Windows command interpreter), where POSIX
# quoting rules do not apply.
def create_command_string_basic(cmd):
    if not cmd:
        return ""
    if len(cmd) == 0:
        return ""
    if isinstance(cmd, str):
        return copy.deepcopy(cmd)
    if isinstance(cmd, list):
        cmd_str = ""
        for cmd_segment in cmd:
            if " " in cmd_segment:
                cmd_str += " " + "\"" + cmd_segment + "\""
            else:
                cmd_str += " " + cmd_segment
        cmd_str = cmd_str.strip()
        return cmd_str
    return ""

# Build a command string, delegating to the quoting style appropriate for the
# target shell. "basic" (default) is cross-platform; "posix" is for POSIX shells.
def create_command_string(cmd, style = "basic"):
    if style == "posix":
        return create_command_string_posix(cmd)
    return create_command_string_basic(cmd)

###########################################################
# Command list
###########################################################

# Split a command string into a list of arguments, preserving spaces inside
# double-quoted substrings.
def create_command_list_enclosed(cmd):
    if not cmd:
        return []
    if len(cmd) == 0:
        return []
    if isinstance(cmd, list):
        return copy.deepcopy(cmd)
    if isinstance(cmd, str):
        try:
            return shlex.split(cmd, posix = False)
        except ValueError:
            return cmd.split(" ")
    return []

# Split a command string into a list of arguments on spaces, without any
# quote awareness.
def create_command_list_split(cmd):
    if not cmd:
        return []
    if len(cmd) == 0:
        return []
    if isinstance(cmd, list):
        return copy.deepcopy(cmd)
    if isinstance(cmd, str):
        return cmd.split(" ")
    return []

# Split a command into a list of arguments, delegating to the requested style.
# "enclosed" (default) preserves spaces inside double-quoted substrings;
# "split" performs a plain space split.
def create_command_list(cmd, style = "enclosed"):
    if style == "split":
        return create_command_list_split(cmd)
    return create_command_list_enclosed(cmd)

###########################################################
# Output
###########################################################

# Decode raw command output to text, ignoring undecodable bytes.
def clean_command_output(output):
    try:
        return output.decode("utf-8", "ignore")
    except Exception:
        return output

###########################################################
# Logging support
###########################################################

# Mask the values following sensitive flags so commands can be safely logged.
def mask_sensitive_args(cmd):
    if isinstance(cmd, str):
        for flag in SENSITIVE_FLAGS:
            if flag in cmd:
                cmd = re.sub(f"{re.escape(flag)}(\\s+|=)\\S+", f"{flag}\\g<1>****", cmd)
        return cmd
    if isinstance(cmd, list):
        masked = []
        skip_next = False
        for arg in cmd:
            if skip_next:
                masked.append("****")
                skip_next = False
            elif arg in SENSITIVE_FLAGS:
                masked.append(arg)
                skip_next = True
            else:
                joined_flag = None
                for flag in SENSITIVE_FLAGS:
                    if isinstance(arg, str) and arg.startswith(flag + "="):
                        joined_flag = flag
                        break
                masked.append(f"{joined_flag}=****" if joined_flag else arg)
        return masked
    return cmd
