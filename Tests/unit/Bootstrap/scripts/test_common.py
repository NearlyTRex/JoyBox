# Imports
import os
import stat
import subprocess

# Third-party imports
import pytest

# Local imports
from bootstrap_helpers import output

pytestmark = pytest.mark.requires_binary("bash", "unshare")


###########################################################
# Day-0 function library
#
# common.sh is sourced by the init_*.sh scripts on a fresh server, as root,
# before Python exists. The contract tests check what it writes; these run it
# and check what it does: which branch it takes, what it refuses, and what it
# leaves behind.
###########################################################

COMMON = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))), "Bootstrap", "scripts", "common.sh")


# Source common.sh and run a snippet; the snippet's $1.. are args
def run(sandbox, body, *args, env = None):
    return sandbox.run_command(["bash", "-c", 'source "$0"\n' + body, COMMON] + [str(arg) for arg in args], env = env)


def mode(sandbox, path):
    return stat.S_IMODE(os.stat(sandbox.host_path(path)).st_mode)


###########################################################
# Preconditions
###########################################################

def test_bash_is_accepted(shell_sandbox):
    result = run(shell_sandbox, "ensure_bash_shell; echo ok")

    assert result.stdout.strip() == "ok"


def test_a_shell_other_than_bash_is_refused(shell_sandbox):
    result = run(shell_sandbox, "unset BASH_VERSION; ensure_bash_shell; echo ok")

    assert result.returncode == 1
    assert "must be run with bash" in result.stdout


def test_root_is_accepted(shell_sandbox):
    result = run(shell_sandbox, "ensure_root_user; echo ok")

    assert result.stdout.strip() == "ok"


def test_an_ordinary_user_is_refused(shell_traced_env):
    # The sandbox is always root, so this runs as the developer instead
    if os.geteuid() == 0:
        pytest.skip("running as root")
    result = subprocess.run(["bash", "-c", 'source "$0"; ensure_root_user; echo ok', COMMON],
                            capture_output = True, text = True, env = shell_traced_env(), check = False)

    assert result.returncode == 1
    assert "Please run this script as root" in result.stdout


def test_an_existing_user_is_accepted(shell_sandbox):
    shell_sandbox.add_user("deploy")

    assert run(shell_sandbox, 'check_user_exists "$1"; echo ok', "deploy").stdout.strip() == "ok"


def test_a_missing_user_is_refused(shell_sandbox):
    result = run(shell_sandbox, 'check_user_exists "$1"; echo ok', "ghost")

    assert result.returncode == 1
    assert "User 'ghost' does not exist" in result.stdout


###########################################################
# Package and manager lists
###########################################################

LIST_WITH_NOISE = "# comment\n\nnginx\n  # indented comment\ncurl\n   \n"


@pytest.mark.parametrize("function, array", [("load_packages", "APT_PACKAGES"), ("load_managers", "MANAGERS")])
def test_a_list_skips_comments_and_blank_lines(shell_sandbox, function, array):
    shell_sandbox.write("/root/list.txt", LIST_WITH_NOISE)

    result = run(shell_sandbox, '%s /root/list.txt; printf "%%s\\n" "${%s[@]}"' % (function, array))

    assert result.returncode == 0
    assert result.stdout.splitlines()[-2:] == ["nginx", "curl"]
    assert "Loaded 2" in result.stdout


@pytest.mark.parametrize("function", ["load_packages", "load_managers"])
def test_a_missing_list_is_refused(shell_sandbox, function):
    result = run(shell_sandbox, "%s /root/absent.txt" % function)

    assert result.returncode == 1
    assert "'/root/absent.txt' not found" in result.stdout


@pytest.mark.parametrize("function", ["load_packages", "load_managers"])
def test_a_list_of_only_comments_is_refused(shell_sandbox, function):
    shell_sandbox.write("/root/list.txt", "# nothing\n\n")

    result = run(shell_sandbox, "%s /root/list.txt" % function)

    assert result.returncode == 1
    assert "No valid" in result.stdout


###########################################################
# Installing managers
###########################################################

@pytest.fixture
def managers(shell_sandbox):
    shell_sandbox.write("/root/managers.txt", "manager_demo.sh\n")
    shell_sandbox.write("/root/checkout/manager_demo.sh", "#!/bin/bash\necho demo\n")
    return shell_sandbox


def install_managers(sandbox, managers_dir = "", env = None):
    return run(sandbox, 'load_managers /root/managers.txt; install_managers "$1"', managers_dir, env = env)


def test_a_manager_is_installed_from_the_checkout(managers):
    result = install_managers(managers, "/root/checkout")

    assert result.returncode == 0
    assert managers.read("/usr/local/bin/manager_demo.sh") == "#!/bin/bash\necho demo\n"
    assert mode(managers, "/usr/local/bin/manager_demo.sh") & stat.S_IXUSR
    assert not managers.calls("curl")


def test_a_manager_is_not_downloaded_without_consent(managers):
    # These get passwordless root, so an unverified fetch is opt-in
    result = install_managers(managers)

    assert result.returncode == 1
    assert "manager_demo.sh was not found in a local checkout" in result.stdout
    assert not managers.calls("curl")


def test_a_manager_is_downloaded_over_https_only_with_consent(managers):
    managers.stub("curl", script = 'while [ $# -gt 1 ]; do [ "$1" = -o ] && echo fetched > "$2"; shift; done\n')

    result = install_managers(managers, env = {"JOYBOX_ALLOW_MANAGER_DOWNLOAD": "1"})

    assert result.returncode == 0
    call = managers.calls("curl")[0]
    assert ["--proto", "=https"] == call[1:3]
    assert call[-1] == "https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_demo.sh"
    assert managers.read("/usr/local/bin/manager_demo.sh") == "fetched\n"


def test_a_failed_download_stops_the_install(managers):
    managers.stub("curl", code = 22)

    result = install_managers(managers, env = {"JOYBOX_ALLOW_MANAGER_DOWNLOAD": "1"})

    assert result.returncode == 1
    assert "Failed to download" in result.stdout


###########################################################
# Sudoers
###########################################################

@pytest.fixture
def grants(shell_sandbox):
    shell_sandbox.write("/root/packages.txt", "nginx\ncurl\n")
    shell_sandbox.write("/root/managers.txt", "manager_nginx.sh\nmanager_certbot.sh\n")
    os.makedirs(shell_sandbox.host_path("/etc/sudoers.d"))
    return shell_sandbox


def setup_sudoers(sandbox):
    return run(sandbox, 'load_packages /root/packages.txt; load_managers /root/managers.txt; '
                        'setup_sudoers deploy /etc/sudoers.d/joybox')


def test_the_grant_names_every_package_action_and_manager(grants):
    result = setup_sudoers(grants)

    assert result.returncode == 0
    sudoers = grants.read("/etc/sudoers.d/joybox")
    assert "    /usr/bin/apt-get install -y nginx, \\\n" in sudoers
    assert "    /usr/bin/apt-get remove -y curl\n" in sudoers
    assert "Cmnd_Alias MANAGER_NGINX = /usr/local/bin/manager_nginx.sh\n" in sudoers
    assert sudoers.rstrip().endswith(
        "deploy ALL=(ALL) NOPASSWD: APT_MANAGE, JOYBOX_VERIFY, MANAGER_NGINX,MANAGER_CERTBOT")
    assert mode(grants, "/etc/sudoers.d/joybox") == 0o440


def test_the_grant_is_checked_by_visudo_before_it_is_installed(grants):
    setup_sudoers(grants)

    call = grants.calls("visudo")[0]
    assert call[:2] == ["-c", "-f"]
    assert call[2] != "/etc/sudoers.d/joybox"


def test_an_invalid_grant_is_never_installed(grants):
    grants.stub("visudo", code = 1)

    result = setup_sudoers(grants)

    assert result.returncode == 1
    assert "Invalid sudoers syntax" in result.stdout
    assert not grants.exists("/etc/sudoers.d/joybox")
    assert not [name for name in os.listdir(grants.host_path("/tmp")) if name.startswith("tmp.")]


def test_cleanup_removes_the_grant(shell_sandbox):
    shell_sandbox.write("/etc/sudoers.d/joybox", "grant\n")

    result = run(shell_sandbox, "cleanup_sudoers /etc/sudoers.d/joybox")

    assert "Removed sudoers file" in result.stdout
    assert not shell_sandbox.exists("/etc/sudoers.d/joybox")


def test_cleanup_without_a_grant_says_so(shell_sandbox):
    result = run(shell_sandbox, "cleanup_sudoers /etc/sudoers.d/joybox")

    assert result.returncode == 0
    assert "No sudoers file to remove" in result.stdout


###########################################################
# htpasswd
###########################################################

HTPASSWD = "/etc/nginx/.htpasswd"


def test_the_first_user_creates_the_file(shell_sandbox):
    result = run(shell_sandbox, "add_htpasswd_user admin secret")

    assert result.returncode == 0
    assert shell_sandbox.ran("htpasswd", "-cbB", HTPASSWD, "admin", "secret")
    assert shell_sandbox.ran("chown", "root:www-data", HTPASSWD)


def test_a_later_user_updates_the_file_and_tightens_its_mode(shell_sandbox):
    shell_sandbox.write(HTPASSWD, "admin:hash\n", mode = 0o644)

    run(shell_sandbox, "add_htpasswd_user admin secret")

    assert shell_sandbox.ran("htpasswd", "-bB", HTPASSWD, "admin", "secret")
    assert mode(shell_sandbox, HTPASSWD) == 0o640


def test_htpasswd_is_installed_when_missing(shell_sandbox):
    os.remove(os.path.join(shell_sandbox.stub_dir, "htpasswd"))
    # Stands in for the package bringing the command with it
    shell_sandbox.write(HTPASSWD, "")

    run(shell_sandbox, "add_htpasswd_user admin secret")

    assert shell_sandbox.ran("apt-get", "install", "-y", "apache2-utils")


def test_removing_htpasswd_deletes_the_file(shell_sandbox):
    shell_sandbox.write(HTPASSWD, "admin:hash\n")

    result = run(shell_sandbox, "remove_htpasswd")

    assert "Removed htpasswd file" in result.stdout
    assert not shell_sandbox.exists(HTPASSWD)


def test_removing_a_missing_htpasswd_says_so(shell_sandbox):
    assert "No htpasswd file found" in run(shell_sandbox, "remove_htpasswd").stdout


###########################################################
# Host services
###########################################################

def test_unattended_upgrades_are_installed_and_enabled(shell_sandbox):
    shell_sandbox.write("/etc/apt/apt.conf.d/.keep", "")

    result = run(shell_sandbox, "configure_unattended_upgrades")

    assert result.returncode == 0
    assert shell_sandbox.ran("apt-get", "install", "-y", "unattended-upgrades")
    assert shell_sandbox.exists("/etc/apt/apt.conf.d/52-joybox-unattended")
    assert shell_sandbox.ran("systemctl", "enable", "--now", "unattended-upgrades")


def test_unattended_upgrades_that_will_not_start_still_finish_configuring(shell_sandbox):
    shell_sandbox.write("/etc/apt/apt.conf.d/.keep", "")
    shell_sandbox.stub("systemctl", code = 1)

    result = run(shell_sandbox, "configure_unattended_upgrades")

    assert result.returncode == 0, output(result)
    assert "Unattended-upgrades configuration complete." in result.stdout


def test_the_firewall_admits_ssh_and_web_before_it_is_enabled(shell_sandbox):
    run(shell_sandbox, "configure_ufw_firewall")

    assert shell_sandbox.calls("ufw") == [["allow", "OpenSSH"], ["allow", "Nginx Full"], ["--force", "enable"]]


def test_fail2ban_jails_are_written_and_loaded(shell_sandbox):
    shell_sandbox.write("/etc/fail2ban/jail.d/.keep", "")

    result = run(shell_sandbox, "configure_fail2ban")

    assert result.returncode == 0
    assert shell_sandbox.exists("/etc/fail2ban/jail.d/nginx-auth.conf")
    assert shell_sandbox.exists("/etc/fail2ban/jail.d/sshd.conf")
    assert shell_sandbox.ran("systemctl", "restart", "fail2ban")


def test_docker_is_installed_and_started(shell_sandbox):
    run(shell_sandbox, "install_docker")

    assert shell_sandbox.ran("apt-get", "install", "-y", "docker.io")
    assert shell_sandbox.ran("systemctl", "enable", "--now", "docker")


def test_nginx_is_installed_and_started(shell_sandbox):
    run(shell_sandbox, "install_nginx")

    assert shell_sandbox.ran("apt-get", "install", "-y", "nginx")
    assert shell_sandbox.ran("systemctl", "enable", "--now", "nginx")


###########################################################
# NGINX hardening
###########################################################

SNIPPET = "/etc/nginx/snippets/ssl-params.conf"


@pytest.fixture
def nginx(shell_sandbox):
    shell_sandbox.write("/etc/nginx/snippets/.keep", "")
    return shell_sandbox


@pytest.mark.parametrize("version", ["1.25.1", "1.26.3"])
def test_http2_is_enabled_by_directive_on_a_new_enough_nginx(nginx, version):
    nginx.stub("nginx", script = 'echo "nginx version: nginx/%s (Ubuntu)" >&2\n' % version)

    result = run(nginx, "configure_security_headers")

    assert nginx.read(SNIPPET).endswith("http2 on;\n")
    assert "Enabled HTTP/2 for nginx %s" % version in result.stdout


@pytest.mark.parametrize("version_output, shown", [("nginx version: nginx/1.24.0", "1.24.0"), ("", "unknown")])
def test_http2_is_left_off_where_the_directive_does_not_exist(nginx, version_output, shown):
    nginx.stub("nginx", script = 'echo "%s" >&2\n' % version_output)

    result = run(nginx, "configure_security_headers")

    assert "http2 on;" not in nginx.read(SNIPPET)
    assert "nginx %s predates the http2 directive" % shown in result.stdout


UBUNTU_NGINX_CONF = """user www-data;
http {

\t##
\t# Basic Settings
\t##

\tsendfile on;
\tinclude /etc/nginx/mime.types;
\tdefault_type application/octet-stream;
}
"""

INCLUDE = "include /etc/nginx/snippets/rate-limit.conf;"


def test_the_rate_limit_zone_is_included_after_the_basic_settings(nginx):
    nginx.write("/etc/nginx/nginx.conf", UBUNTU_NGINX_CONF)

    result = run(nginx, "configure_rate_limit")

    conf = nginx.read("/etc/nginx/nginx.conf")
    assert conf.count(INCLUDE) == 1
    assert conf.index("# Basic Settings") < conf.index(INCLUDE) < conf.index("sendfile on;")
    assert "Rate limiting include added" in result.stdout
    assert "rate=5r/s" in nginx.read("/etc/nginx/snippets/rate-limit.conf")


def test_without_a_basic_settings_banner_the_include_follows_the_default_type(nginx):
    nginx.write("/etc/nginx/nginx.conf", "http {\n\tdefault_type application/octet-stream;\n}\n")

    run(nginx, "configure_rate_limit")

    conf = nginx.read("/etc/nginx/nginx.conf")
    assert conf.count(INCLUDE) == 1
    assert conf.index("default_type") < conf.index(INCLUDE)


def test_the_rate_limit_include_is_added_once(nginx):
    nginx.write("/etc/nginx/nginx.conf", UBUNTU_NGINX_CONF)

    run(nginx, "configure_rate_limit")
    result = run(nginx, "configure_rate_limit")

    assert nginx.read("/etc/nginx/nginx.conf").count(INCLUDE) == 1
    assert "Rate limiting include already exists" in result.stdout


###########################################################
# ModSecurity
###########################################################

MODSEC = "/etc/nginx/modsec"


# curl writes the recommended config; git clone makes a rule set with rules
def stub_downloads(sandbox, with_example = True):
    sandbox.stub("curl", script = (
        'while [ $# -gt 1 ]; do [ "$1" = -o ] && echo "SecRuleEngine DetectionOnly" > "$2"; shift; done\n'))
    example = 'touch "$dest/crs-setup.conf.example"\n' if with_example else ""
    sandbox.stub("git", script = (
        'if [ "$1" = clone ]; then dest="${@: -1}"; mkdir -p "$dest/.git" "$dest/rules"\n'
        '    touch "$dest/rules/REQUEST-901.conf"\n' + example + 'fi\n'))


def test_modsecurity_is_set_up_from_scratch(shell_sandbox):
    stub_downloads(shell_sandbox)

    result = run(shell_sandbox, "configure_modsecurity")

    assert result.returncode == 0
    assert shell_sandbox.read(MODSEC + "/modsecurity.conf") == "SecRuleEngine On\n"
    assert shell_sandbox.ran("git", "clone", "--depth", "1", "--branch", "v4.29.0")
    assert shell_sandbox.exists(MODSEC + "/crs/crs-setup.conf")
    assert "include %s/crs/rules/*.conf;" % MODSEC in shell_sandbox.read(MODSEC + "/main.conf")
    assert "Found 1 CRS rule files" in result.stdout


def test_a_rule_set_without_an_example_gets_a_basic_setup(shell_sandbox):
    stub_downloads(shell_sandbox, with_example = False)

    result = run(shell_sandbox, "configure_modsecurity")

    assert "creating basic configuration" in result.stdout
    assert "SecDefaultAction" in shell_sandbox.read(MODSEC + "/crs/crs-setup.conf")


def test_an_existing_setup_is_kept_and_the_rule_set_moved_to_the_pin(shell_sandbox):
    stub_downloads(shell_sandbox)
    shell_sandbox.write(MODSEC + "/modsecurity.conf", "SecRuleEngine On\n")
    shell_sandbox.write(MODSEC + "/crs/.git/HEAD", "")
    shell_sandbox.write(MODSEC + "/crs/crs-setup.conf", "mine\n")
    shell_sandbox.write(MODSEC + "/crs/rules/a.conf", "")

    result = run(shell_sandbox, "configure_modsecurity")

    assert not shell_sandbox.ran("curl")
    assert shell_sandbox.ran("git", "-C", MODSEC + "/crs", "checkout", "-q", "v4.29.0")
    assert shell_sandbox.read(MODSEC + "/crs/crs-setup.conf") == "mine\n"
    assert "crs-setup.conf already exists" in result.stdout


def test_a_rule_set_that_cannot_fetch_is_still_moved_to_the_pin(shell_sandbox):
    shell_sandbox.stub("git", script = '[ "$3" = fetch ] && exit 1; exit 0\n')
    shell_sandbox.write(MODSEC + "/modsecurity.conf", "SecRuleEngine On\n")
    shell_sandbox.write(MODSEC + "/crs/.git/HEAD", "")
    shell_sandbox.write(MODSEC + "/crs/crs-setup.conf", "mine\n")
    shell_sandbox.write(MODSEC + "/crs/rules/a.conf", "")

    result = run(shell_sandbox, "configure_modsecurity")

    assert result.returncode == 0, output(result)
    assert shell_sandbox.ran("git", "-C", MODSEC + "/crs", "checkout", "-q", "v4.29.0")


def test_a_pin_that_cannot_be_checked_out_keeps_the_existing_rules(shell_sandbox):
    shell_sandbox.stub("git", script = '[ "$3" = checkout ] && exit 1; exit 0\n')
    shell_sandbox.write(MODSEC + "/modsecurity.conf", "SecRuleEngine On\n")
    shell_sandbox.write(MODSEC + "/crs/.git/HEAD", "")
    shell_sandbox.write(MODSEC + "/crs/crs-setup.conf", "mine\n")

    result = run(shell_sandbox, "configure_modsecurity")

    assert "could not check out v4.29.0" in result.stdout
    assert "ModSecurity setup may be incomplete" in result.stdout


def test_a_rule_set_directory_that_is_not_a_clone_is_replaced(shell_sandbox):
    stub_downloads(shell_sandbox)
    shell_sandbox.write(MODSEC + "/crs/stray.txt", "")

    result = run(shell_sandbox, "configure_modsecurity")

    assert "not a git repository. Removing" in result.stdout
    assert not shell_sandbox.exists(MODSEC + "/crs/stray.txt")
    assert shell_sandbox.ran("git", "clone")


###########################################################
# NGINX stream module
###########################################################

STREAM_NGINX_CONF = "user www-data;\nhttp {\n\tsendfile on;\n}\n"


@pytest.fixture
def stream(shell_sandbox):
    shell_sandbox.write("/etc/nginx/nginx.conf", STREAM_NGINX_CONF)
    return shell_sandbox


def test_the_stream_module_is_installed_loaded_and_included(stream):
    result = run(stream, "configure_nginx_stream_module")

    assert result.returncode == 0, output(result)
    conf = stream.read("/etc/nginx/nginx.conf")
    assert conf.startswith("load_module modules/ngx_stream_module.so;\n")
    assert conf.index("stream {") < conf.index("http {")
    assert "include /etc/nginx/streams-enabled/*;" in conf
    assert stream.ran("apt-get", "install", "-y", "libnginx-mod-stream")
    assert stream.exists("/etc/nginx/streams-available")
    assert stream.ran("systemctl", "reload-or-restart", "nginx")


def test_a_module_loaded_by_the_package_is_not_loaded_twice(stream):
    stream.stub("dpkg", stdout = "ii  libnginx-mod-stream  1.24.0\n")
    stream.write("/etc/nginx/modules-enabled/50-mod-stream.conf",
                 'load_module modules/ngx_stream_module.so;\n')

    result = run(stream, "configure_nginx_stream_module")

    assert "package already installed" in result.stdout
    assert "load_module" not in stream.read("/etc/nginx/nginx.conf")
    assert "Stream block added" in result.stdout


def test_a_configured_stream_module_changes_nothing(stream):
    stream.write("/etc/nginx/nginx.conf", "load_module modules/ngx_stream_module.so;\nstream {\n}\n" + STREAM_NGINX_CONF)

    result = run(stream, "configure_nginx_stream_module")

    assert "already configured" in result.stdout
    assert not stream.ran("nginx", "-t")
    assert not stream.ran("systemctl", "reload-or-restart")


def test_a_failed_config_test_restores_nginx_conf(stream):
    stream.stub("nginx", code = 1)

    result = run(stream, "configure_nginx_stream_module")

    assert result.returncode == 1
    assert "Restored nginx.conf" in result.stdout
    assert stream.read("/etc/nginx/nginx.conf") == STREAM_NGINX_CONF
    assert not stream.ran("systemctl", "reload-or-restart")


###########################################################
# sshd hardening
###########################################################

DROPIN = "/etc/ssh/sshd_config.d/00-joybox.conf"
ENFORCED = "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n"


@pytest.fixture
def sshd(shell_sandbox):
    shell_sandbox.add_user("deploy")
    shell_sandbox.write("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy\n")
    shell_sandbox.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
    shell_sandbox.stub("sshd", script = '[ "$1" = -T ] && printf "%s"\nexit 0\n' % ENFORCED)
    return shell_sandbox


def harden(sandbox):
    return run(sandbox, "configure_sshd_hardening deploy")


def test_sshd_is_hardened_and_reloaded(sshd):
    sshd.write("/etc/ssh/sshd_config.d/99-joybox.conf", "old\n")

    result = harden(sshd)

    assert result.returncode == 0, output(result)
    assert "AllowUsers deploy\n" in sshd.read(DROPIN)
    assert mode(sshd, DROPIN) == 0o644
    assert not sshd.exists("/etc/ssh/sshd_config.d/99-joybox.conf")
    assert sshd.ran("systemctl", "reload", "ssh")
    assert sshd.read("/etc/ssh/sshd_config").count("Include") == 1


@pytest.mark.parametrize("keys", [None, ""])
def test_hardening_refuses_without_a_key_to_get_back_in(sshd, keys):
    if keys is None:
        os.remove(sshd.host_path("/home/deploy/.ssh/authorized_keys"))
    else:
        sshd.write("/home/deploy/.ssh/authorized_keys", keys)

    result = harden(sshd)

    assert result.returncode == 1
    assert "authorized_keys is missing or empty" in result.stdout
    assert not sshd.exists(DROPIN)


def test_a_config_without_the_include_gets_one(sshd):
    sshd.write("/etc/ssh/sshd_config", "Port 22\n")

    harden(sshd)

    assert sshd.read("/etc/ssh/sshd_config").startswith("Include /etc/ssh/sshd_config.d/*.conf\n")


def test_an_invalid_config_is_reverted_before_the_daemon_sees_it(sshd):
    sshd.stub("sshd", code = 1)

    result = harden(sshd)

    assert result.returncode == 1
    assert not sshd.exists(DROPIN)
    assert not sshd.ran("systemctl", "reload")


def test_the_unit_is_reloaded_under_its_other_name(sshd):
    sshd.stub("systemctl", script = '[ "$2" = ssh ] && exit 5; exit 0\n')

    assert harden(sshd).returncode == 0
    assert sshd.ran("systemctl", "reload", "sshd")


def test_a_setting_overridden_elsewhere_fails_the_hardening(sshd):
    sshd.stub("sshd", script = '[ "$1" = -T ] && printf "permitrootlogin no\\npasswordauthentication yes\\n"\nexit 0\n')

    result = harden(sshd)

    assert result.returncode == 1
    assert "does not enforce 'passwordauthentication no'" in result.stdout


###########################################################
# Docker
###########################################################

def test_a_user_joins_the_docker_group(shell_sandbox):
    shell_sandbox.add_user("deploy")
    shell_sandbox.stub("groups", stdout = "deploy : deploy\n")

    result = run(shell_sandbox, "configure_docker_group deploy")

    assert shell_sandbox.ran("usermod", "-aG", "docker", "deploy")
    assert not shell_sandbox.ran("groupadd")
    assert "Added 'deploy'" in result.stdout


def test_a_missing_docker_group_is_created(shell_sandbox):
    shell_sandbox.write("/etc/group", "root:x:0:\ndeploy:x:1000:\n")
    shell_sandbox.stub("groups", stdout = "deploy : deploy\n")

    run(shell_sandbox, "configure_docker_group deploy")

    assert shell_sandbox.ran("groupadd", "docker")


def test_a_member_is_left_alone(shell_sandbox):
    shell_sandbox.stub("groups", stdout = "deploy : deploy docker\n")

    result = run(shell_sandbox, "configure_docker_group deploy")

    assert "already in the 'docker' group" in result.stdout
    assert not shell_sandbox.ran("usermod")


def test_an_existing_metadata_rule_is_not_added_again(shell_sandbox):
    run(shell_sandbox, "configure_docker_security")

    assert shell_sandbox.ran("iptables", "-C", "DOCKER-USER")
    assert not shell_sandbox.ran("iptables", "-I")


def test_docker_is_restarted_with_its_daemon_config(shell_sandbox):
    shell_sandbox.stub("iptables", code = 1)

    run(shell_sandbox, "configure_docker_security")

    assert shell_sandbox.exists("/etc/docker/daemon.json")
    assert shell_sandbox.ran("iptables", "-I", "DOCKER-USER", "-i", "docker0", "-d", "169.254.169.254", "-j", "DROP")
    assert shell_sandbox.ran("systemctl", "restart", "docker")


###########################################################
# Storage Box
###########################################################

@pytest.fixture
def storage(shell_sandbox):
    shell_sandbox.add_user("deploy", uid = 1000)
    shell_sandbox.write("/etc/fstab", "")
    for name in ["ssh-copy-id", "sshpass", "mountpoint"]:
        shell_sandbox.stub(name, code = 1 if name == "mountpoint" else 0)
    return shell_sandbox


def setup_storage(sandbox, *extra):
    return run(sandbox, 'setup_storage_box "$@"', "deploy", "u1", "u1.example.de", *extra)


FSTAB_ENTRY = ('u1@u1.example.de:/home /mnt/storage fuse.sshfs noauto,x-systemd.automount,_netdev,user,'
               'idmap=user,identityfile="/home/deploy/.ssh/id_rsa",port=23,allow_other,uid=1000,gid=1000 0 0\n')


def test_the_storage_box_is_keyed_mounted_and_persisted(storage):
    result = setup_storage(storage)

    assert result.returncode == 0, output(result)
    assert storage.calls("ssh-keygen")[0][-2:] == ["-f", "/home/deploy/.ssh/id_rsa"]
    assert storage.ran("ssh-copy-id", "-p", "23", "-s", "-i", "/home/deploy/.ssh/id_rsa.pub", "u1@u1.example.de")
    assert storage.read("/etc/fstab") == FSTAB_ENTRY
    assert storage.ran("chown", "deploy:deploy", "/mnt/storage")
    assert storage.calls("sshfs")[0][-2:] == ["u1@u1.example.de:/home", "/mnt/storage"]
    assert not storage.ran("apt-get")


def test_a_rerun_neither_rekeys_nor_duplicates_the_mount(storage):
    storage.write("/home/deploy/.ssh/id_rsa", "key")
    storage.stub("mountpoint", code = 0)

    setup_storage(storage)
    result = setup_storage(storage)

    assert not storage.ran("ssh-keygen")
    assert storage.read("/etc/fstab") == FSTAB_ENTRY
    assert not storage.ran("sshfs")
    assert "/mnt/storage is already mounted" in result.stdout


def test_an_unattended_upload_reads_the_password_from_a_file(storage):
    os.remove(os.path.join(storage.stub_dir, "sshpass"))
    os.remove(os.path.join(storage.stub_dir, "sshfs"))
    storage.write("/root/storage.pass", "secret")

    setup_storage(storage, "/home", "/mnt/storage", "/root/storage.pass")

    assert storage.ran("apt-get", "install", "-y", "sshfs")
    assert storage.ran("apt-get", "install", "-y", "sshpass")
    assert storage.ran("chown", "deploy", "/root/storage.pass")


###########################################################
# Repository and local storage
###########################################################

def test_the_repository_is_cloned_as_the_user(shell_sandbox):
    result = run(shell_sandbox, "setup_joybox_repo deploy")

    assert result.returncode == 0
    assert shell_sandbox.ran("chown", "deploy:deploy", "/mnt/repositories")
    assert shell_sandbox.ran("git", "clone", "https://github.com/NearlyTRex/JoyBox", "/mnt/repositories/JoyBox")


def test_an_existing_clone_is_kept(shell_sandbox):
    shell_sandbox.write("/srv/repos/JoyBox/.git/HEAD", "")

    result = run(shell_sandbox, "setup_joybox_repo deploy /srv/repos")

    assert "already exists" in result.stdout
    assert not shell_sandbox.ran("git")
    assert not shell_sandbox.ran("chown")


def test_local_storage_has_the_layout_the_apps_expect(shell_sandbox):
    result = run(shell_sandbox, "setup_local_storage deploy")

    assert result.returncode == 0
    for path in ["/mnt/storage/Music/Audiobook", "/mnt/storage/Backups"]:
        assert os.path.isdir(shell_sandbox.host_path(path))
    assert shell_sandbox.ran("chown", "-R", "deploy:deploy", "/mnt/storage")
    assert "ffmpeg is not installed" in result.stdout


def test_local_storage_is_seeded_with_placeholder_media_once(shell_sandbox):
    shell_sandbox.stub("ffmpeg", script = 'echo audio > "${@: -1}"\n')

    run(shell_sandbox, "setup_local_storage deploy /mnt/media")
    run(shell_sandbox, "setup_local_storage deploy /mnt/media")

    assert len(shell_sandbox.calls("ffmpeg")) == 1
    assert shell_sandbox.read("/mnt/media/Music/Audiobook/placeholder.mp3") == "audio\n"
