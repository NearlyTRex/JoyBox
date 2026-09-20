# Server hardening checks.
#
# Asserts that the hardening a setup applied actually took effect, rather than
# that it was merely configured. Everything here reads state through a
# connection, so the same checks run against a rehearsal guest or a real
# server without anything being installed on either.
#
# The parsing is kept apart from the gathering: a parser takes the raw output
# of one command and says what it means, which is the part worth testing.

# Imports
import json
import re

# Local imports
import joybox.logger as logger

# What a single check concluded
PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

###########################################################
# Results
###########################################################

class CheckResult:

    # Constructor
    def __init__(self, section, outcome, message, detail = None):
        self.section = section
        self.outcome = outcome
        self.message = message
        self.detail = detail or []

    # Check if this counts against the run
    def is_failure(self):
        return self.outcome == FAIL

    # Format for display
    def __str__(self):
        return "  %-4s  %s" % (self.outcome, self.message)

# Count the failures in a set of results
def count_failures(results):
    return len([result for result in results if result.is_failure()])

# Format results for display, grouped by section
def format_results(results):
    lines = []
    section = None
    for result in results:
        if result.section != section:
            section = result.section
            lines.append("")
            lines.append("== %s" % section)
        lines.append(str(result))
        for line in result.detail:
            lines.append("          %s" % line)
    return "\n".join(lines)

###########################################################
# Parsers
#
# Each takes the raw output of one command. Kept separate from running it so
# the interpretation can be tested against captured output.
###########################################################

# Ports a listening socket accepts from anywhere, from ss -tlnH.
# Docker publishes past ufw, so this is the check that catches a container
# bound to every interface.
def parse_wildcard_listeners(output, allowed_ports = None):
    if allowed_ports is None:
        allowed_ports = ["22", "80", "443"]
    wildcards = []
    for line in (output or "").splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        if not re.match(r"^(0\.0\.0\.0|\*|\[::\]):", local):
            continue
        port = local.rsplit(":", 1)[-1]
        if port in allowed_ports:
            continue
        wildcards.append(local)
    return wildcards

# Containers published on every interface, from docker ps
def parse_exposed_containers(output):
    exposed = []
    for line in (output or "").splitlines():
        if not line.strip():
            continue
        if "0.0.0.0" in line or "[::]" in line:
            exposed.append(line.strip())
    return exposed

# The effective sshd settings, from sshd -T
def parse_sshd_settings(output):
    settings = {}
    for line in (output or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1].strip()
    return settings

# Whether ufw reports itself active, from ufw status
def parse_ufw_active(output):
    return "status: active" in (output or "").lower()

# The rules ufw is allowing, from ufw status
def parse_ufw_allowed(output):
    return [line.strip() for line in (output or "").splitlines() if "ALLOW" in line]

# The uid.gid suffix docker appends to its root directory when userns-remap is
# active, from docker info. Configured is not the same as active.
def parse_userns_remap_suffix(output):
    match = re.search(r"(\d+\.\d+)\s*$", (output or "").strip())
    return match.group(1) if match else None

# Whether a docker daemon config declares a key
def parse_daemon_keys(contents):
    try:
        data = json.loads(contents or "")
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    return sorted(data.keys())

# What an nginx configuration dump says about rate limiting, from nginx -T
def parse_nginx_rate_limiting(output):
    contents = output or ""
    return {
        "zone_defined": "limit_req_zone" in contents,
        "zone_used": bool(re.search(r"^\s*limit_req\s+zone=", contents, re.MULTILINE)),
        "tokens_off": bool(re.search(r"server_tokens\s+off", contents)),
    }

# Which of the jails asked about are running, from repeated fail2ban-client
# status calls keyed by jail name
def parse_running_jails(statuses):
    return sorted(name for name, running in (statuses or {}).items() if running)

# Whether unattended upgrades will actually activate what they install
def parse_unattended_upgrades(contents):
    contents = contents or ""
    return {
        "present": bool(contents.strip()),
        "automatic_reboot": bool(
            re.search(r'Automatic-Reboot\s+"true"', contents, re.IGNORECASE)),
    }

# How many responses in a burst were refused
def count_rate_limited(codes, limited_code = "503"):
    return len([code for code in (codes or []) if str(code).strip() == limited_code])

###########################################################
# Checks
#
# Each runs commands through a connection and turns what comes back into
# results. A connection to the local machine and one over ssh behave the same,
# so nothing has to be installed on the server being checked.
###########################################################

# Check if a command is available on the other side
def has_command(connection, name):
    return connection.run_return_code(["command", "-v", name]) == 0

# Read a command's output as text
def read_output(connection, cmd, sudo = False):
    output = connection.run_output(cmd, sudo = sudo)
    if isinstance(output, bytes):
        output = output.decode(errors = "ignore")
    return output or ""

# No container may publish on every interface. Docker writes its own DNAT
# rules ahead of ufw's chains, so a published port is not governed by the
# firewall at all.
def check_container_ports(connection, allowed_ports = None):
    section = "Container port bindings"
    results = []
    if not has_command(connection, "docker"):
        results.append(CheckResult(section, SKIP, "docker is not installed"))
    else:
        exposed = parse_exposed_containers(
            read_output(connection, ["docker", "ps", "--format", "{{.Names}} {{.Ports}}"]))
        if exposed:
            results.append(CheckResult(
                section, FAIL, "containers published on all interfaces", exposed))
        else:
            results.append(CheckResult(
                section, PASS, "no container publishes on 0.0.0.0"))

    # The listening socket is the second opinion, and the one that counts
    if has_command(connection, "ss"):
        wildcards = parse_wildcard_listeners(
            read_output(connection, ["ss", "-tlnH"]), allowed_ports)
        if wildcards:
            results.append(CheckResult(
                section, FAIL, "unexpected wildcard listeners", wildcards))
        else:
            results.append(CheckResult(
                section, PASS, "no unexpected wildcard listeners"))
    return results

# The firewall has to be running, not merely installed
def check_firewall(connection):
    section = "Firewall"
    if not has_command(connection, "ufw"):
        return [CheckResult(section, SKIP, "ufw is not installed")]
    output = read_output(connection, ["ufw", "status"], sudo = True)
    if not parse_ufw_active(output):
        return [CheckResult(section, FAIL, "ufw is installed but not active")]
    return [CheckResult(
        section, PASS, "ufw is active", parse_ufw_allowed(output))]

# Password login has to be off and root login restricted
def check_sshd(connection):
    section = "sshd"
    if not has_command(connection, "sshd"):
        return [CheckResult(section, SKIP, "sshd is not installed")]
    settings = parse_sshd_settings(read_output(connection, ["sshd", "-T"], sudo = True))
    if not settings:
        return [CheckResult(section, FAIL, "could not read the effective sshd config")]
    results = []
    if settings.get("passwordauthentication") == "no":
        results.append(CheckResult(section, PASS, "password authentication is disabled"))
    else:
        results.append(CheckResult(section, FAIL, "password authentication is still enabled"))
    if settings.get("permitrootlogin") in ("no", "prohibit-password"):
        results.append(CheckResult(section, PASS, "root login is restricted"))
    else:
        results.append(CheckResult(section, FAIL, "root login is not restricted"))
    return results

# The jails have to be running. On Ubuntu 24.04 the packaged sshd jail matches
# nothing unless told to read journald, and says nothing about it.
def check_fail2ban(connection, jails = None):
    section = "fail2ban"
    if jails is None:
        jails = ["sshd", "nginx-http-auth"]
    if not has_command(connection, "fail2ban-client"):
        return [CheckResult(section, SKIP, "fail2ban is not installed")]
    statuses = {}
    for jail in jails:
        statuses[jail] = connection.run_return_code(
            ["fail2ban-client", "status", jail], sudo = True) == 0
    results = []
    running = parse_running_jails(statuses)
    for jail in jails:
        if jail in running:
            results.append(CheckResult(section, PASS, "jail '%s' is running" % jail))
        else:
            results.append(CheckResult(section, FAIL, "jail '%s' is not running" % jail))
    return results

# The daemon has to have the hardening applied, and userns-remap has to be
# active rather than only declared
def check_docker_hardening(connection, daemon_file = "/etc/docker/daemon.json"):
    section = "Docker daemon"
    results = []
    if not connection.does_file_or_directory_exist(daemon_file):
        return [CheckResult(section, SKIP, "no %s" % daemon_file)]
    declared = parse_daemon_keys(connection.read_file(daemon_file))
    for key in ["userns-remap", "no-new-privileges"]:
        if key in declared:
            results.append(CheckResult(section, PASS, "%s is configured" % key))
        else:
            results.append(CheckResult(section, FAIL, "%s is missing" % key))
    if has_command(connection, "docker"):
        suffix = parse_userns_remap_suffix(
            read_output(connection, ["docker", "info", "--format", "{{.DockerRootDir}}"]))
        if suffix:
            results.append(CheckResult(
                section, PASS, "userns-remap is active (root dir suffix %s)" % suffix))
        else:
            results.append(CheckResult(
                section, FAIL,
                "userns-remap does not appear active - DockerRootDir has no uid suffix"))
    return results

# A rate limit zone that nothing consumes limits nothing
def check_rate_limiting(connection, domain = None, burst_size = 40):
    section = "Rate limiting and headers"
    if not has_command(connection, "nginx"):
        return [CheckResult(section, SKIP, "nginx is not installed")]
    state = parse_nginx_rate_limiting(read_output(connection, ["nginx", "-T"], sudo = True))
    results = []
    for key, good, bad in [
        ("zone_defined", "limit_req_zone is defined", "limit_req_zone is missing"),
        ("zone_used", "limit_req consumes the zone",
         "limit_req is missing - the zone is defined but never applied"),
        ("tokens_off", "server_tokens is off", "server_tokens is not off"),
    ]:
        results.append(CheckResult(section, PASS if state[key] else FAIL,
                                   good if state[key] else bad))

    # Configuration is not proof; burst past the rate and expect refusals
    if domain and has_command(connection, "curl"):
        codes = []
        for _ in range(burst_size):
            codes.append(read_output(connection, [
                "curl", "-s",
                "-o", "/dev/null",
                "-w", "%{http_code}",
                "--max-time", "5",
                "https://%s/" % domain]).strip())
        refused = count_rate_limited(codes)
        if refused:
            results.append(CheckResult(
                section, PASS,
                "a %d-request burst was rate limited (%d refused)" % (burst_size, refused)))
        else:
            results.append(CheckResult(
                section, FAIL, "a %d-request burst was never rate limited" % burst_size))
    return results

# Patches that install but never activate leave the box reporting itself
# patched while running the vulnerable kernel
def check_unattended_upgrades(
    connection, config_file = "/etc/apt/apt.conf.d/52-joybox-unattended"):
    section = "Unattended upgrades"
    if not connection.does_file_or_directory_exist(config_file):
        return [CheckResult(section, FAIL, "no %s" % config_file)]
    state = parse_unattended_upgrades(connection.read_file(config_file))
    results = [CheckResult(section, PASS, "the unattended-upgrades config is present")]
    if state["automatic_reboot"]:
        results.append(CheckResult(section, PASS, "automatic reboot is enabled"))
    else:
        results.append(CheckResult(
            section, FAIL,
            "automatic reboot is not enabled - kernel updates install but never activate"))
    return results

###########################################################
# Running them all
###########################################################

# Every check, in the order they are reported
CHECKS = [
    check_container_ports,
    check_firewall,
    check_sshd,
    check_fail2ban,
    check_docker_hardening,
    check_rate_limiting,
    check_unattended_upgrades,
]

# Run every check against a connection
def verify_hardening(connection, domain = None, verbose = False):
    results = []
    for check in CHECKS:
        if check is check_rate_limiting:
            results += check(connection, domain = domain)
        else:
            results += check(connection)
    if verbose:
        logger.log_info(format_results(results))
    return results
