# Secrets kept out of the configuration.
#
# A field in JoyBox.ini can hold a reference instead of the secret itself, so
# the file is worth nothing to anyone who reads it - a log line, a screenshot,
# a backup of the home directory, a command run while looking at something
# else. The secret is fetched when that field is actually asked for and kept
# in memory for the life of the process, never written anywhere.
#
# This is a guard against a secret being read by accident. It is not a guard
# against a program that is running as you deliberately reading one: anything
# able to run the tool below can resolve a reference, which is the same
# authority it would have had over a plain file.

# Imports
import os
import subprocess

# Local imports
import joybox.logger as logger

# What a reference looks like. 1Password's own syntax, so the same string
# works with the tool directly, and with op inject and op run.
secret_reference_prefix = "op://"

# The tool that resolves a reference
secret_tool = "op"

# Where it is looked for when it is not on the path
secret_tool_paths = ["/usr/bin/op", "/usr/local/bin/op", "/opt/1Password/op"]

# How long to wait. Resolving prompts the desktop app to unlock, so this is a
# person reaching for a key rather than a machine answering.
secret_timeout_seconds = 120

# Secrets already fetched this run, so a field read in a loop asks once
_resolved = {}

###########################################################
# References
###########################################################

# Determine whether a configured value is a reference rather than a secret
def is_secret_reference(value):
    return isinstance(value, str) and value.strip().startswith(secret_reference_prefix)

# Find the tool that resolves references
def get_secret_tool():
    for candidate in secret_tool_paths:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, secret_tool)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

# Build the command that resolves one reference
def get_secret_command(tool, reference):
    return [tool, "read", "--no-newline", reference]

###########################################################
# Resolving
###########################################################

# Forget everything fetched this run
def clear_resolved_secrets():
    _resolved.clear()

# Resolve one reference
# Run with the ordinary subprocess rather than the command module, which logs
# what it runs and hands output through several layers; a secret should touch
# as little as possible on its way to the caller.
def resolve_secret_reference(reference, verbose = False):
    reference = reference.strip()
    if reference in _resolved:
        return _resolved[reference]
    tool = get_secret_tool()
    if not tool:
        logger.log_error(
            "%s holds a secret reference but %s was not found; install the "
            "1Password command line tool" % (reference, secret_tool))
        return None
    if verbose:
        logger.log_info("Resolving %s" % reference)
    try:
        result = subprocess.run(
            get_secret_command(tool, reference),
            capture_output = True,
            text = True,
            timeout = secret_timeout_seconds)
    except subprocess.TimeoutExpired:
        logger.log_error(
            "Timed out resolving %s; the vault may be waiting to be unlocked"
            % reference)
        return None
    except Exception as e:
        logger.log_error("Unable to resolve %s" % reference)
        logger.log_error(e)
        return None
    if result.returncode != 0:

        # The tool's complaint names the item, not its contents
        detail = (result.stderr or "").strip().splitlines()
        logger.log_error("Unable to resolve %s" % reference)
        if detail:
            logger.log_error(detail[0])
        return None
    value = result.stdout
    if not value:
        logger.log_error("%s resolved to nothing" % reference)
        return None
    _resolved[reference] = value
    return value

# Resolve a configured value when it is a reference, and leave it alone
# otherwise
def resolve_value(value, verbose = False):
    if not is_secret_reference(value):
        return value
    return resolve_secret_reference(value, verbose = verbose)
