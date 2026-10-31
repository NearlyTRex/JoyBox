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
import json
import os
import subprocess
import uuid

# Local imports
import joybox.logger as logger
import joybox.serialization as serialization

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

# What the tool prints when it has no account to read from. Set once seen, so
# a run that reads many references reports it once rather than for each.
no_account_marker = "No accounts configured"
_no_account = {"seen": False}

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

# Split a reference into vault, item, section and field; the section is None
# for op://vault/item/field. None when it is not a reference to one field.
def parse_secret_reference(reference):
    if not is_secret_reference(reference):
        return None
    parts = reference.strip()[len(secret_reference_prefix):].split("/")
    if any(not part for part in parts):
        return None
    if len(parts) == 3:
        return (parts[0], parts[1], None, parts[2])
    if len(parts) == 4:
        return tuple(parts)
    return None

###########################################################
# Resolving
###########################################################

# Run the tool, giving it no input unless there is some to send. A value being
# stored goes on standard input rather than the command line, where other
# processes can read it.
def run_secret_tool(cmd, action, reference, input_text = None):
    try:
        return subprocess.run(
            cmd,
            check = False,
            input = input_text,
            stdin = None if input_text is not None else subprocess.DEVNULL,
            capture_output = True,
            text = True,
            timeout = secret_timeout_seconds)
    except subprocess.TimeoutExpired:
        logger.log_error(
            "Timed out %s %s; the vault may be waiting to be unlocked" % (action, reference))
    except Exception as e:
        logger.log_error("Unable to run %s for %s" % (secret_tool, reference))
        logger.log_error(e)
    return None

# Log a refusal from the tool with the first line of its complaint, which
# names the item, not its contents
def log_tool_refusal(message, result):
    logger.log_error(message)
    detail = (result.stderr or "").strip().splitlines()
    if detail:
        logger.log_error(detail[0])

# Forget everything fetched this run
def clear_resolved_secrets():
    _resolved.clear()
    _no_account["seen"] = False

# Resolve one reference
# Run with the ordinary subprocess rather than the command module, which logs
# what it runs and hands output through several layers; a secret should touch
# as little as possible on its way to the caller. The tool gets no input: with
# none it fails and says how to sign in, where with a terminal it offers to add
# an account and then prompts into output that is being captured.
def resolve_secret_reference(reference, verbose = False):
    reference = reference.strip()
    if reference in _resolved:
        return _resolved[reference]
    if _no_account["seen"]:
        return None
    tool = get_secret_tool()
    if not tool:
        logger.log_error(
            "%s holds a secret reference but %s was not found; install the "
            "1Password command line tool" % (reference, secret_tool))
        return None
    if verbose:
        logger.log_info("Resolving %s" % reference)
    result = run_secret_tool(get_secret_command(tool, reference), "resolving", reference)
    if not result:
        return None
    if result.returncode != 0:

        # The tool's complaint names the item, not its contents
        detail = (result.stderr or "").strip().splitlines()
        logger.log_error("Unable to resolve %s" % reference)
        if no_account_marker in (result.stderr or ""):
            _no_account["seen"] = True
            for line in detail:
                if line.strip():
                    logger.log_error(line.strip())
            logger.log_error(
                "Sign in to the 1Password app and turn on its CLI integration, then run this "
                "again; see Docs/reference/secrets.md")
        elif detail:
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

###########################################################
# Storing
###########################################################

# Determine whether an item field is the one a reference names
def is_referenced_field(field, field_name, section_name):
    if field_name not in (field.get("label"), field.get("id")):
        return False
    if section_name is None:
        return True
    section = field.get("section") or {}
    return section_name in (section.get("label"), section.get("id"))

# Set a field on an item's JSON, adding it as a concealed field, and its
# section, when the item has none by that name
def set_item_field(item, field_name, section_name, value):
    fields = item.setdefault("fields", [])
    matches = [field for field in fields if is_referenced_field(field, field_name, section_name)]
    if len(matches) > 1:
        return False
    if matches:
        matches[0]["value"] = value
        return True
    field = {"id": uuid.uuid4().hex, "label": field_name, "type": "CONCEALED", "value": value}
    if section_name is not None:
        sections = item.setdefault("sections", [])
        section = next((s for s in sections if section_name in (s.get("label"), s.get("id"))), None)
        if not section:
            section = {"id": uuid.uuid4().hex, "label": section_name}
            sections.append(section)
        field["section"] = {"id": section["id"]}
    fields.append(field)
    return True

# Read an item with its values, or writing it back would blank them
def read_secret_item(tool, vault_name, item_name, reference):
    result = run_secret_tool(
        [tool, "item", "get", item_name, "--vault", vault_name, "--format", "json", "--reveal"],
        "reading", reference)
    if not result:
        return None
    if result.returncode != 0:
        log_tool_refusal("Unable to read the item for %s" % reference, result)
        return None
    item = serialization.parse_json_string(result.stdout)
    if not isinstance(item, dict) or not item.get("id"):
        logger.log_error("Unable to read the item for %s" % reference)
        return None
    return item

# Write an item back whole
def write_secret_item(tool, vault_name, item, reference):
    vault_id = (item.get("vault") or {}).get("id", vault_name)
    result = run_secret_tool(
        [tool, "item", "edit", item["id"], "--vault", vault_id],
        "storing", reference, input_text = json.dumps(item))
    if not result:
        return False
    if result.returncode != 0:
        log_tool_refusal("Unable to store %s" % reference, result)
        return False
    return True

# Store a value in the field a reference names. The whole item is read and
# written back, so it must not hold a passkey, which a JSON template drops.
def store_secret_reference(reference, value, verbose = False):
    parsed = parse_secret_reference(reference)
    if not parsed:
        logger.log_error("%s is not a reference to one field" % reference)
        return False
    vault_name, item_name, section_name, field_name = parsed
    tool = get_secret_tool()
    if not tool:
        logger.log_error("Unable to store %s; install the 1Password command line tool" % reference)
        return False
    if verbose:
        logger.log_info("Storing %s" % reference)
    item = read_secret_item(tool, vault_name, item_name, reference)
    if not item:
        return False
    if not set_item_field(item, field_name, section_name, value):
        logger.log_error("%s names more than one field" % reference)
        return False
    if not write_secret_item(tool, vault_name, item, reference):
        return False
    _resolved.pop(reference.strip(), None)
    return True
