# Imports
import os

# Third-party imports
import pytest

pytestmark = pytest.mark.requires_binary("bash", "unshare")


###########################################################
# Day-0 web server setup
#
# init_nginx.sh installs nginx and puts every protection in front of it in
# one pass; the functions it calls are covered by test_common.py, so these
# check that the script reaches them and stops on its preconditions.
###########################################################

SCRIPT = "Bootstrap/scripts/init_nginx.sh"
UBUNTU_NGINX_CONF = (
    "http {\n\n\t##\n\t# Basic Settings\n\t##\n\n\tsendfile on;\n"
    "\tdefault_type application/octet-stream;\n}\n")


@pytest.fixture
def server(shell_sandbox):
    # What the packages bring with them; apt-get is a stub here
    for directory in ["/etc/apt/apt.conf.d", "/etc/fail2ban/jail.d", "/etc/nginx/snippets"]:
        os.makedirs(shell_sandbox.host_path(directory))
    shell_sandbox.write("/etc/nginx/nginx.conf", UBUNTU_NGINX_CONF)
    shell_sandbox.stub("nginx", script = '[ "$1" = -v ] && echo "nginx version: nginx/1.24.0" >&2\nexit 0\n')
    shell_sandbox.stub("curl", script = (
        'while [ $# -gt 1 ]; do [ "$1" = -o ] && echo "SecRuleEngine DetectionOnly" > "$2"; shift; done\n'))
    shell_sandbox.stub("git", script = (
        'if [ "$1" = clone ]; then dest="${@: -1}"; mkdir -p "$dest/.git" "$dest/rules"\n'
        '    touch "$dest/rules/REQUEST-901.conf" "$dest/crs-setup.conf.example"\nfi\n'))
    return shell_sandbox


def test_the_server_is_set_up_end_to_end(server):
    result = server.run(SCRIPT)

    assert result.returncode == 0, result.stdout + result.stderr
    assert server.ran("apt-get", "install", "-y", "nginx")
    assert server.ran("apt-get", "install", "-y", "unattended-upgrades")
    assert server.ran("ufw", "--force", "enable")
    assert server.exists("/etc/fail2ban/jail.d/nginx-auth.conf")
    assert server.exists("/etc/nginx/snippets/ssl-params.conf")
    assert "include /etc/nginx/snippets/rate-limit.conf;" in server.read("/etc/nginx/nginx.conf")
    assert server.read("/etc/nginx/modsec/modsecurity.conf") == "SecRuleEngine On\n"
    assert "stream {" in server.read("/etc/nginx/nginx.conf")


def test_a_failing_step_stops_the_setup(server):
    server.stub("ufw", code = 1)

    result = server.run(SCRIPT)

    assert result.returncode != 0
    assert not server.exists("/etc/nginx/snippets/ssl-params.conf")


def test_the_script_refuses_to_run_without_its_library(shell_sandbox):
    result = shell_sandbox.run_command(
        ["bash", "-c", 'source "$1"', "/nowhere/init_nginx.sh", os.path.join(shell_sandbox.repo_root, SCRIPT)])

    assert result.returncode == 1
    assert "Cannot find or read /nowhere/common.sh" in result.stdout
    assert not shell_sandbox.calls()
