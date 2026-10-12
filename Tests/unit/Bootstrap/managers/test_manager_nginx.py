# Imports
import os

# Third-party imports
import pytest


###########################################################
# Nginx manager
#
# The account runs this as root without a password to put site, stream and
# snippet configurations in place, so it only copies from the staging
# directories, never takes a path where a file name belongs, and never
# enables a configuration nginx rejects.
###########################################################

SCRIPT = "Bootstrap/managers/manager_nginx.sh"
SITES_AVAILABLE = "/etc/nginx/sites-available"
SITES_ENABLED = "/etc/nginx/sites-enabled"
STREAMS_AVAILABLE = "/etc/nginx/streams-available"
STREAMS_ENABLED = "/etc/nginx/streams-enabled"
SNIPPETS = "/etc/nginx/snippets"


@pytest.fixture
def server(shell_sandbox):
    for directory in [SITES_AVAILABLE, SITES_ENABLED]:
        os.makedirs(shell_sandbox.host_path(directory))
    return shell_sandbox


def run(server, *args):
    return server.run(SCRIPT, *args)


def link_target(server, path):
    return os.readlink(server.host_path(path))


###########################################################
# Usage
###########################################################

@pytest.mark.parametrize("args", [[], ["install_conf"]])
def test_too_few_arguments_prints_usage(server, args):
    result = run(server, *args)

    assert result.returncode == 1
    assert "Usage:" in result.stdout


def test_an_unknown_operation_is_refused(server):
    result = run(server, "delete_everything", "x")

    assert result.returncode == 1
    assert "Invalid operation 'delete_everything'" in result.stdout
    assert "Usage:" in result.stdout


###########################################################
# Source paths
###########################################################

@pytest.mark.parametrize("operation", ["install_conf", "install_stream_conf", "install_snippet", "copy_html"])
def test_a_relative_source_is_refused(server, operation):
    result = run(server, operation, "tmp/site.conf")

    assert result.returncode == 1
    assert "Path must be absolute" in result.stdout


@pytest.mark.parametrize("source", ["/etc/shadow", "/tmp/../etc/shadow", "/tmpfoo/site.conf"])
def test_a_source_outside_the_staging_directories_is_refused(server, source):
    result = run(server, "install_conf", source)

    assert result.returncode == 1
    assert "outside the allowed source directories" in result.stdout


def test_a_staged_link_out_of_the_staging_directory_is_refused(server):
    # Resolved before the check, or a link in /tmp would copy out any file
    os.symlink("/etc/passwd", server.host_path("/tmp/site.conf"))

    result = run(server, "install_conf", "/tmp/site.conf")

    assert result.returncode == 1
    assert "'/etc/passwd' is outside" in result.stdout


def test_a_missing_source_is_refused(server):
    result = run(server, "install_conf", "/tmp/absent.conf")

    assert result.returncode == 1
    assert "Path /tmp/absent.conf does not exist" in result.stdout


###########################################################
# Sites
###########################################################

def test_install_conf_copies_into_sites_available(server):
    server.write("/tmp/site.conf", "server {}\n")

    result = run(server, "install_conf", "/tmp/site.conf")

    assert result.returncode == 0
    assert server.read(SITES_AVAILABLE + "/site.conf") == "server {}\n"


def test_install_conf_accepts_var_tmp(server):
    server.write("/var/tmp/site.conf", "server {}\n")

    assert run(server, "install_conf", "/var/tmp/site.conf").returncode == 0
    assert server.exists(SITES_AVAILABLE + "/site.conf")


def test_link_conf_enables_a_site_nginx_accepts(server):
    server.write(SITES_AVAILABLE + "/site.conf", "server {}\n")

    result = run(server, "link_conf", "site.conf")

    assert result.returncode == 0
    assert link_target(server, SITES_ENABLED + "/site.conf") == SITES_AVAILABLE + "/site.conf"
    assert server.ran("nginx", "-t")


def test_a_site_nginx_rejects_is_not_left_enabled(server):
    # A link nginx rejects would stop every later reload, not just this site
    server.write(SITES_AVAILABLE + "/site.conf", "server {\n")
    server.stub("nginx", code = 1)

    result = run(server, "link_conf", "site.conf")

    assert result.returncode == 1
    assert "site.conf was not enabled" in result.stdout
    assert not server.exists(SITES_ENABLED + "/site.conf")


def test_a_site_already_enabled_is_kept_when_nginx_rejects_the_set(server):
    server.write(SITES_AVAILABLE + "/site.conf", "server {}\n")
    os.symlink(SITES_AVAILABLE + "/site.conf", server.host_path(SITES_ENABLED + "/site.conf"))
    server.stub("nginx", code = 1)

    result = run(server, "link_conf", "site.conf")

    assert result.returncode == 1
    assert "rejects the configuration with" in result.stdout
    assert server.exists(SITES_ENABLED + "/site.conf")


def test_link_conf_refuses_a_site_that_is_not_available(server):
    result = run(server, "link_conf", "absent.conf")

    assert result.returncode == 1
    assert "'absent.conf' does not exist" in result.stdout
    assert not server.ran("nginx")


@pytest.mark.parametrize("operation", [
    "link_conf", "remove_conf", "link_stream_conf", "remove_stream_conf", "remove_snippet"])
@pytest.mark.parametrize("name", ["../nginx.conf", "sub/site.conf"])
def test_a_file_name_cannot_reach_another_directory(server, operation, name):
    result = run(server, operation, name)

    assert result.returncode == 1
    assert "Directory traversal" in result.stdout


def test_remove_conf_removes_both_copies(server):
    server.write(SITES_AVAILABLE + "/site.conf", "server {}\n")
    os.symlink(SITES_AVAILABLE + "/site.conf", server.host_path(SITES_ENABLED + "/site.conf"))

    result = run(server, "remove_conf", "site.conf")

    assert result.returncode == 0
    assert not server.exists(SITES_ENABLED + "/site.conf")
    assert not server.exists(SITES_AVAILABLE + "/site.conf")


def test_remove_conf_removes_a_link_whose_site_is_already_gone(server):
    # Left behind, it fails nginx -t for every later change
    os.symlink(SITES_AVAILABLE + "/site.conf", server.host_path(SITES_ENABLED + "/site.conf"))

    result = run(server, "remove_conf", "site.conf")

    assert result.returncode == 0
    assert not server.exists(SITES_ENABLED + "/site.conf")


def test_remove_conf_of_an_unknown_site_succeeds(server):
    assert run(server, "remove_conf", "absent.conf").returncode == 0


###########################################################
# Streams
###########################################################

def test_install_stream_conf_creates_the_stream_directories(server):
    server.write("/tmp/aim.conf", "server { listen 5190; }\n")

    result = run(server, "install_stream_conf", "/tmp/aim.conf")

    assert result.returncode == 0
    assert server.read(STREAMS_AVAILABLE + "/aim.conf") == "server { listen 5190; }\n"
    assert os.path.isdir(server.host_path(STREAMS_ENABLED))


def test_link_stream_conf_enables_a_stream(server):
    server.write(STREAMS_AVAILABLE + "/aim.conf", "server {}\n")

    result = run(server, "link_stream_conf", "aim.conf")

    assert result.returncode == 0
    assert link_target(server, STREAMS_ENABLED + "/aim.conf") == STREAMS_AVAILABLE + "/aim.conf"


def test_a_stream_nginx_rejects_is_not_left_enabled(server):
    server.write(STREAMS_AVAILABLE + "/aim.conf", "server {\n")
    server.stub("nginx", code = 1)

    result = run(server, "link_stream_conf", "aim.conf")

    assert result.returncode == 1
    assert not server.exists(STREAMS_ENABLED + "/aim.conf")


def test_link_stream_conf_refuses_a_stream_that_is_not_available(server):
    result = run(server, "link_stream_conf", "absent.conf")

    assert result.returncode == 1
    assert "Stream configuration file 'absent.conf' does not exist" in result.stdout


def test_remove_stream_conf_removes_both_copies(server):
    server.write(STREAMS_AVAILABLE + "/aim.conf", "server {}\n")
    os.makedirs(server.host_path(STREAMS_ENABLED))
    os.symlink(STREAMS_AVAILABLE + "/aim.conf", server.host_path(STREAMS_ENABLED + "/aim.conf"))

    result = run(server, "remove_stream_conf", "aim.conf")

    assert result.returncode == 0
    assert not server.exists(STREAMS_ENABLED + "/aim.conf")
    assert not server.exists(STREAMS_AVAILABLE + "/aim.conf")


def test_remove_stream_conf_of_an_unknown_stream_succeeds(server):
    assert run(server, "remove_stream_conf", "absent.conf").returncode == 0


###########################################################
# Firewall
###########################################################

def active_firewall(server, allow_code = 0, delete_code = 0):
    server.stub("ufw", script = (
        'case "$1" in\n'
        '    status) echo "Status: active" ;;\n'
        '    allow) exit %d ;;\n'
        '    delete) exit %d ;;\n'
        'esac\n') % (allow_code, delete_code))


def test_open_port_allows_it_on_an_active_firewall(server):
    active_firewall(server)

    result = run(server, "open_port", "5190")

    assert result.returncode == 0
    assert server.ran("ufw", "allow", "5190")
    assert "Port 5190 opened successfully" in result.stdout


def test_open_port_fails_when_the_rule_is_refused(server):
    active_firewall(server, allow_code = 1)

    result = run(server, "open_port", "5190")

    assert result.returncode == 1
    assert "Failed to open port 5190" in result.stdout


@pytest.mark.parametrize("operation", ["open_port", "close_port"])
def test_an_inactive_firewall_is_left_alone(server, operation):
    server.stub("ufw", stdout = "Status: inactive\n")

    result = run(server, operation, "5190")

    assert result.returncode == 0
    assert "UFW is not active" in result.stdout
    assert not server.ran("ufw", "allow")
    assert not server.ran("ufw", "delete")


def test_close_port_deletes_the_rule(server):
    active_firewall(server)

    result = run(server, "close_port", "5190")

    assert result.returncode == 0
    assert server.ran("ufw", "delete", "allow", "5190")
    assert "Port 5190 closed successfully" in result.stdout


def test_close_port_tolerates_a_rule_that_does_not_exist(server):
    active_firewall(server, delete_code = 1)

    result = run(server, "close_port", "5190")

    assert result.returncode == 0
    assert "Rule may not exist" in result.stdout


@pytest.mark.parametrize("operation", ["open_port", "close_port"])
@pytest.mark.parametrize("port", ["0", "65536", "22/tcp", "-1"])
def test_an_invalid_port_is_refused(server, operation, port):
    result = run(server, operation, port)

    assert result.returncode == 1
    assert "Invalid port number" in result.stdout
    assert not server.calls("ufw")


@pytest.mark.parametrize("operation", ["open_port", "close_port"])
def test_extra_port_arguments_are_refused(server, operation):
    result = run(server, operation, "80", "443")

    assert result.returncode == 1
    assert "Usage: " in result.stdout
    assert not server.calls("ufw")


###########################################################
# Snippets and HTML
###########################################################

def test_install_snippet_copies_into_snippets(server):
    server.write("/tmp/headers.conf", "add_header X-Test 1;\n")

    result = run(server, "install_snippet", "/tmp/headers.conf")

    assert result.returncode == 0
    assert server.read(SNIPPETS + "/headers.conf") == "add_header X-Test 1;\n"


def test_remove_snippet_removes_it(server):
    server.write(SNIPPETS + "/headers.conf", "add_header X-Test 1;\n")

    result = run(server, "remove_snippet", "headers.conf")

    assert result.returncode == 0
    assert "Snippet headers.conf removed" in result.stdout
    assert not server.exists(SNIPPETS + "/headers.conf")


def test_remove_snippet_of_an_unknown_snippet_succeeds(server):
    result = run(server, "remove_snippet", "absent.conf")

    assert result.returncode == 0
    assert "not found, nothing to remove" in result.stdout


def test_copy_html_copies_and_prepares_the_acme_directory(server):
    server.write("/tmp/index.html", "<p>hi</p>\n")

    result = run(server, "copy_html", "/tmp/index.html")

    assert result.returncode == 0
    assert server.read("/var/www/html/index.html") == "<p>hi</p>\n"
    assert os.path.isdir(server.host_path("/var/www/html/.well-known/acme-challenge"))


###########################################################
# Service control
###########################################################

@pytest.mark.parametrize("action", ["reload", "restart", "status", "start", "stop", "enable", "disable"])
def test_systemctl_acts_on_nginx_only(server, action):
    result = run(server, "systemctl", action)

    assert result.returncode == 0
    assert server.calls("systemctl") == [[action, "nginx"]]


def test_a_failed_systemctl_is_reported(server):
    server.stub("systemctl", code = 1)

    result = run(server, "systemctl", "reload")

    assert result.returncode == 1
    assert "Failed to execute systemctl reload nginx" in result.stdout


def test_an_unknown_systemctl_action_is_refused(server):
    result = run(server, "systemctl", "mask")

    assert result.returncode == 1
    assert "Invalid systemctl command" in result.stdout
    assert not server.calls("systemctl")
