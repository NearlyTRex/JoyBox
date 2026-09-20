# Third-party imports
import pytest

# Local imports
from joybox import hardening


###########################################################
# Reading command output
#
# The part worth testing: what a command's output means. Captured from the
# real tools, so a change in their format shows up here rather than as a check
# that quietly always passes.
###########################################################

SS_OUTPUT = """LISTEN 0      4096       127.0.0.1:8080       0.0.0.0:*
LISTEN 0      4096         0.0.0.0:22          0.0.0.0:*
LISTEN 0      4096         0.0.0.0:80          0.0.0.0:*
LISTEN 0      511             [::]:443            [::]:*
LISTEN 0      4096       127.0.0.1:9000       0.0.0.0:*
"""


###########################################################
# Listening sockets
###########################################################

def test_a_loopback_listener_is_not_a_wildcard():
    # This is the shape every app is supposed to have.
    assert hardening.parse_wildcard_listeners(SS_OUTPUT) == []


def test_a_wildcard_listener_on_an_unexpected_port_is_found():
    output = SS_OUTPUT + "LISTEN 0 4096 0.0.0.0:9090 0.0.0.0:*\n"

    assert hardening.parse_wildcard_listeners(output) == ["0.0.0.0:9090"]


@pytest.mark.parametrize("port", ["22", "80", "443"])
def test_the_expected_wildcard_ports_are_allowed(port):
    output = "LISTEN 0 4096 0.0.0.0:%s 0.0.0.0:*\n" % port

    assert hardening.parse_wildcard_listeners(output) == []


def test_an_ipv6_wildcard_is_found():
    output = "LISTEN 0 511 [::]:9090 [::]:*\n"

    assert hardening.parse_wildcard_listeners(output) == ["[::]:9090"]


def test_a_bare_asterisk_is_a_wildcard():
    output = "LISTEN 0 511 *:9090 *:*\n"

    assert hardening.parse_wildcard_listeners(output) == ["*:9090"]


def test_the_allowed_ports_can_be_chosen():
    output = "LISTEN 0 4096 0.0.0.0:9090 0.0.0.0:*\n"

    assert hardening.parse_wildcard_listeners(output, allowed_ports = ["9090"]) == []


@pytest.mark.parametrize("output", ["", None, "garbage\n", "too few\n"])
def test_unusable_socket_output_finds_nothing(output):
    assert hardening.parse_wildcard_listeners(output) == []


###########################################################
# Published containers
###########################################################

def test_a_loopback_publication_is_not_exposed():
    output = "filebrowser 127.0.0.1:8080->80/tcp\nnavidrome 127.0.0.1:4533->4533/tcp\n"

    assert hardening.parse_exposed_containers(output) == []


def test_a_container_on_every_interface_is_exposed():
    # Docker's rules sit ahead of ufw, so this is not firewalled at all.
    output = "filebrowser 0.0.0.0:8080->80/tcp\n"

    assert hardening.parse_exposed_containers(output) == ["filebrowser 0.0.0.0:8080->80/tcp"]


def test_an_ipv6_publication_is_exposed():
    output = "jenkins [::]:8080->8080/tcp\n"

    assert hardening.parse_exposed_containers(output) != []


def test_one_exposed_container_among_many_is_found():
    output = ("filebrowser 127.0.0.1:8080->80/tcp\n"
              "jenkins 0.0.0.0:8081->8080/tcp\n"
              "navidrome 127.0.0.1:4533->4533/tcp\n")

    assert len(hardening.parse_exposed_containers(output)) == 1


def test_no_containers_are_exposed_when_none_run():
    assert hardening.parse_exposed_containers("") == []


###########################################################
# sshd
###########################################################

SSHD_OUTPUT = """port 22
addressfamily any
permitrootlogin prohibit-password
passwordauthentication no
kbdinteractiveauthentication no
x11forwarding no
"""


def test_the_effective_settings_are_read():
    settings = hardening.parse_sshd_settings(SSHD_OUTPUT)

    assert settings["passwordauthentication"] == "no"
    assert settings["permitrootlogin"] == "prohibit-password"


def test_setting_names_are_lowercased():
    # sshd -T lowercases them, but a hand written config may not.
    settings = hardening.parse_sshd_settings("PasswordAuthentication no\n")

    assert settings["passwordauthentication"] == "no"


def test_a_value_with_spaces_is_kept_whole():
    settings = hardening.parse_sshd_settings("allowusers deploy admin\n")

    assert settings["allowusers"] == "deploy admin"


@pytest.mark.parametrize("output", ["", None, "\n\n"])
def test_unreadable_sshd_output_yields_nothing(output):
    assert hardening.parse_sshd_settings(output) == {}


###########################################################
# Firewall
###########################################################

def test_an_active_firewall_is_recognised():
    assert hardening.parse_ufw_active("Status: active\n") is True


def test_an_inactive_firewall_is_recognised():
    assert hardening.parse_ufw_active("Status: inactive\n") is False


def test_the_status_check_ignores_case():
    assert hardening.parse_ufw_active("status: ACTIVE\n") is True


def test_the_allowed_rules_are_listed():
    output = ("Status: active\n\n"
              "To          Action    From\n"
              "22/tcp      ALLOW     Anywhere\n"
              "443/tcp     ALLOW     Anywhere\n")

    assert len(hardening.parse_ufw_allowed(output)) == 2


###########################################################
# Docker
###########################################################

def test_an_active_remap_shows_a_uid_suffix():
    # Configured is not active; the daemon moves its root when it is.
    assert hardening.parse_userns_remap_suffix(
        "/var/lib/docker/165536.165536") == "165536.165536"


def test_an_unremapped_root_has_no_suffix():
    assert hardening.parse_userns_remap_suffix("/var/lib/docker") is None


@pytest.mark.parametrize("output", ["", None, "error"])
def test_unusable_docker_output_shows_no_suffix(output):
    assert hardening.parse_userns_remap_suffix(output) is None


def test_the_daemon_keys_are_read():
    contents = '{"userns-remap": "default", "no-new-privileges": true}'

    assert hardening.parse_daemon_keys(contents) == ["no-new-privileges", "userns-remap"]


@pytest.mark.parametrize("contents", ["", None, "not json", "[]", "null"])
def test_an_unusable_daemon_config_declares_nothing(contents):
    assert hardening.parse_daemon_keys(contents) == []


###########################################################
# nginx
###########################################################

def test_a_zone_that_is_defined_and_used_is_recognised():
    contents = ("limit_req_zone $binary_remote_addr zone=mylimit:10m rate=5r/s;\n"
                "    limit_req zone=mylimit burst=20 nodelay;\n"
                "server_tokens off;\n")
    state = hardening.parse_nginx_rate_limiting(contents)

    assert state == {"zone_defined": True, "zone_used": True, "tokens_off": True}


def test_a_zone_defined_but_never_used_is_caught():
    # This exact shape limited nothing while looking configured.
    contents = "limit_req_zone $binary_remote_addr zone=mylimit:10m rate=5r/s;\n"
    state = hardening.parse_nginx_rate_limiting(contents)

    assert state["zone_defined"] is True
    assert state["zone_used"] is False


def test_a_commented_out_limit_does_not_count():
    contents = ("limit_req_zone $binary_remote_addr zone=mylimit:10m;\n"
                "#    limit_req zone=mylimit burst=20;\n")

    assert hardening.parse_nginx_rate_limiting(contents)["zone_used"] is False


def test_server_tokens_being_on_is_caught():
    assert hardening.parse_nginx_rate_limiting("server_tokens on;")["tokens_off"] is False


@pytest.mark.parametrize("contents", ["", None])
def test_an_empty_configuration_has_nothing_set(contents):
    state = hardening.parse_nginx_rate_limiting(contents)

    assert not any(state.values())


###########################################################
# fail2ban
###########################################################

def test_the_running_jails_are_listed():
    assert hardening.parse_running_jails(
        {"sshd": True, "nginx-http-auth": False}) == ["sshd"]


def test_no_running_jails_lists_nothing():
    assert hardening.parse_running_jails({"sshd": False}) == []


@pytest.mark.parametrize("statuses", [{}, None])
def test_nothing_asked_about_lists_nothing(statuses):
    assert hardening.parse_running_jails(statuses) == []


###########################################################
# Unattended upgrades
###########################################################

def test_a_config_with_automatic_reboot_is_recognised():
    contents = ('APT::Periodic::Unattended-Upgrade "1";\n'
                'Unattended-Upgrade::Automatic-Reboot "true";\n')
    state = hardening.parse_unattended_upgrades(contents)

    assert state == {"present": True, "automatic_reboot": True}


def test_a_config_without_automatic_reboot_is_caught():
    # Patches install but never activate, so the box reports itself patched
    # while still running the vulnerable kernel.
    contents = 'APT::Periodic::Unattended-Upgrade "1";\n'
    state = hardening.parse_unattended_upgrades(contents)

    assert state["present"] is True
    assert state["automatic_reboot"] is False


def test_automatic_reboot_set_to_false_is_caught():
    contents = 'Unattended-Upgrade::Automatic-Reboot "false";\n'

    assert hardening.parse_unattended_upgrades(contents)["automatic_reboot"] is False


@pytest.mark.parametrize("contents", ["", None, "   \n"])
def test_an_empty_config_is_not_present(contents):
    assert hardening.parse_unattended_upgrades(contents)["present"] is False


###########################################################
# Rate limit bursts
###########################################################

def test_refused_responses_are_counted():
    assert hardening.count_rate_limited(["200", "200", "503", "503"]) == 2


def test_no_refusals_count_as_none():
    assert hardening.count_rate_limited(["200"] * 40) == 0


def test_response_codes_are_stripped():
    assert hardening.count_rate_limited([" 503 ", "503\n"]) == 2


@pytest.mark.parametrize("codes", [[], None])
def test_no_responses_count_as_none(codes):
    assert hardening.count_rate_limited(codes) == 0
