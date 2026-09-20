# The system hosts file.
#
# Used to point a test domain and its subdomains at a local VM, so the
# workstation's resolver finds them without touching DNS. The entries live in
# a managed block, so removing them leaves the rest of the file alone.

# Imports
import os

# Local imports
import joybox.logger as logger
import joybox.settings as settings
import joybox.textblock as textblock
from joybox import platform_info

# Markers
MARKER_BEGIN = "# BEGIN JoyBox local testing"
MARKER_END = "# END JoyBox local testing"

# Get the hosts file path for this platform
def get_hosts_file():
    if platform_info.is_windows_platform():
        return os.path.join(
            os.environ.get("SystemRoot", "C:\\Windows"),
            "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"

# Get the subdomains the server components are configured to use.
# Read from the settings rather than listed here, so a new component with a
# subdomain of its own is picked up without this needing an edit.
def get_configured_subdomains():
    subdomains = []
    for section in settings.get_sections(throw_exception = False) or []:
        for field in settings.get_fields(section, throw_exception = False) or []:
            if not field.endswith("_subdomain"):
                continue
            value = settings.get_value(section, field, throw_exception = False)
            if value and value not in subdomains:
                subdomains.append(value)
    return sorted(subdomains)

# Build the host entries for a domain
def build_entries(address, domain, subdomains = None):
    if subdomains is None:
        subdomains = get_configured_subdomains()
    entries = ["%s %s" % (address, domain)]
    for subdomain in subdomains:
        entries.append("%s %s.%s" % (address, subdomain, domain))
    return entries

# Read the hosts file
def read_hosts(hosts_file = None, verbose = False, exit_on_failure = False):
    hosts_file = hosts_file or get_hosts_file()
    try:
        with open(hosts_file, "r", encoding = "utf-8") as handle:
            return handle.read()
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % hosts_file)
            logger.log_error(e, quit_program = True)
        return None

# Write the hosts file
def write_hosts(contents, hosts_file = None, verbose = False, pretend_run = False,
                exit_on_failure = False):
    hosts_file = hosts_file or get_hosts_file()
    try:
        if verbose:
            logger.log_info("Writing %s" % hosts_file)
        if not pretend_run:
            with open(hosts_file, "w", encoding = "utf-8") as handle:
                handle.write(contents)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to write %s" % hosts_file)
            logger.log_error(e, quit_program = True)
        return False

# Check if the managed entries are present
def has_entries(hosts_file = None):
    contents = read_hosts(hosts_file)
    if contents is None:
        return False
    return textblock.has_block(contents, MARKER_BEGIN, MARKER_END)

# Point a domain and its subdomains at an address
def set_entries(
    address,
    domain,
    subdomains = None,
    hosts_file = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    hosts_file = hosts_file or get_hosts_file()
    contents = read_hosts(hosts_file, exit_on_failure = exit_on_failure)
    if contents is None:
        return False
    entries = build_entries(address, domain, subdomains)
    if verbose:
        logger.log_info("Pointing %s at %s" % (domain, address))
        for entry in entries:
            logger.log_info("  %s" % entry)
    return write_hosts(
        contents = textblock.set_block(contents, entries, MARKER_BEGIN, MARKER_END),
        hosts_file = hosts_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Remove the managed entries
def remove_entries(
    hosts_file = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    hosts_file = hosts_file or get_hosts_file()
    contents = read_hosts(hosts_file, exit_on_failure = exit_on_failure)
    if contents is None:
        return False
    if not textblock.has_block(contents, MARKER_BEGIN, MARKER_END):
        if verbose:
            logger.log_info("No JoyBox entries in %s" % hosts_file)
        return True
    if verbose:
        logger.log_info("Removing the JoyBox entries from %s" % hosts_file)
    return write_hosts(
        contents = textblock.remove_block(contents, MARKER_BEGIN, MARKER_END),
        hosts_file = hosts_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# List the managed entries
def get_entries(hosts_file = None):
    contents = read_hosts(hosts_file)
    if contents is None:
        return []
    body = textblock.read_block_body(contents, MARKER_BEGIN, MARKER_END)
    if not body:
        return []
    return [line.strip() for line in body.splitlines() if line.strip()]
