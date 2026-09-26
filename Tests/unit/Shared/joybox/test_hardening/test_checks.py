# Third-party imports
import pytest

# Local imports
from joybox import hardening
from hardening_helpers import FakeServer, all_passed, hardened_server, outcomes


###########################################################
# Checks against a server
#
# Each check reads state through a connection, so a fake one can put the
# server into any state. The point of every check is that it fails when the
# hardening was configured but did not take effect.
###########################################################

def only(results):
    assert len(results) == 1, [str(result) for result in results]
    return results[0]


###########################################################
# Container ports
###########################################################

def test_loopback_bound_containers_pass(server):
    server.install("docker", "filebrowser 127.0.0.1:8080->80/tcp")
    server.install("ss", "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*")

    assert all_passed(hardening.check_container_ports(server))


def test_a_container_on_every_interface_fails(server):
    server.install("docker", "filebrowser 0.0.0.0:8080->80/tcp")
    server.install("ss", "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*")
    results = hardening.check_container_ports(server)

    assert hardening.count_failures(results) == 1


def test_the_exposed_container_is_named(server):
    server.install("docker", "filebrowser 0.0.0.0:8080->80/tcp")
    results = hardening.check_container_ports(server)
    failure = [result for result in results if result.is_failure()][0]

    assert any("filebrowser" in line for line in failure.detail)


def test_a_wildcard_socket_fails_even_when_docker_looks_clean(server):
    # docker reports what it asked for; ss reports what is actually listening.
    server.install("docker", "filebrowser 127.0.0.1:8080->80/tcp")
    server.install("ss", "LISTEN 0 4096 0.0.0.0:9090 0.0.0.0:*")

    assert hardening.count_failures(hardening.check_container_ports(server)) == 1


def test_no_docker_skips_that_half(server):
    server.install("ss", "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*")
    results = hardening.check_container_ports(server)

    assert any(result.outcome == hardening.SKIP for result in results)
    assert hardening.count_failures(results) == 0


def test_no_tools_at_all_checks_nothing(server):
    assert hardening.count_failures(hardening.check_container_ports(server)) == 0


###########################################################
# Firewall
###########################################################

def test_an_active_firewall_passes(server):
    server.install("ufw", "Status: active\n22/tcp ALLOW Anywhere\n")

    assert only(hardening.check_firewall(server)).outcome == hardening.PASS


def test_an_installed_but_inactive_firewall_fails(server):
    # Installing ufw without enabling it is the easy mistake.
    server.install("ufw", "Status: inactive\n")

    assert only(hardening.check_firewall(server)).outcome == hardening.FAIL


def test_no_firewall_is_skipped(server):
    assert only(hardening.check_firewall(server)).outcome == hardening.SKIP


def test_the_allowed_rules_are_reported(server):
    server.install("ufw", "Status: active\n22/tcp ALLOW Anywhere\n443/tcp ALLOW Anywhere\n")

    assert len(only(hardening.check_firewall(server)).detail) == 2


###########################################################
# sshd
###########################################################

def test_a_hardened_sshd_passes(server):
    server.install("sshd", "passwordauthentication no\npermitrootlogin prohibit-password\n")

    assert all_passed(hardening.check_sshd(server))


def test_password_authentication_still_on_fails(server):
    server.install("sshd", "passwordauthentication yes\npermitrootlogin no\n")
    results = outcomes(hardening.check_sshd(server))

    assert results["password authentication is still enabled"] == hardening.FAIL


@pytest.mark.parametrize("value", ["no", "prohibit-password"])
def test_either_restricted_root_setting_passes(server, value):
    server.install("sshd", "passwordauthentication no\npermitrootlogin %s\n" % value)

    assert all_passed(hardening.check_sshd(server))


def test_root_login_permitted_fails(server):
    server.install("sshd", "passwordauthentication no\npermitrootlogin yes\n")
    results = outcomes(hardening.check_sshd(server))

    assert results["root login is not restricted"] == hardening.FAIL


def test_an_unreadable_sshd_config_fails(server):
    # Not knowing is not the same as being fine.
    server.install("sshd", "")

    assert only(hardening.check_sshd(server)).outcome == hardening.FAIL


def test_no_sshd_is_skipped(server):
    assert only(hardening.check_sshd(server)).outcome == hardening.SKIP


###########################################################
# fail2ban
###########################################################

def test_running_jails_pass(server):
    server.install("fail2ban-client", "", code = 0)

    assert all_passed(hardening.check_fail2ban(server))


def test_a_jail_that_is_not_running_fails(server):
    # The packaged sshd jail matches nothing on 24.04 unless told to read
    # journald, and reports no error about it.
    server.install("fail2ban-client", "", code = 1)
    results = hardening.check_fail2ban(server)

    assert hardening.count_failures(results) == 2


def test_each_named_jail_is_checked(server):
    server.install("fail2ban-client", "", code = 0)
    results = hardening.check_fail2ban(server, jails = ["sshd"])

    assert len(results) == 1
    assert "sshd" in results[0].message


def test_no_fail2ban_is_skipped(server):
    assert only(hardening.check_fail2ban(server)).outcome == hardening.SKIP


###########################################################
# Docker hardening
###########################################################

DAEMON = "/etc/docker/daemon.json"


def test_a_hardened_daemon_passes(server):
    server.add_file(DAEMON, '{"userns-remap": "default", "no-new-privileges": true}')
    server.install("docker", "/var/lib/docker/165536.165536")

    assert all_passed(hardening.check_docker_hardening(server))


@pytest.mark.parametrize("missing", ["userns-remap", "no-new-privileges"])
def test_a_missing_daemon_key_fails(server, missing):
    keys = {"userns-remap": "default", "no-new-privileges": True}
    del keys[missing]
    import json
    server.add_file(DAEMON, json.dumps(keys))
    server.install("docker", "/var/lib/docker/165536.165536")
    results = outcomes(hardening.check_docker_hardening(server))

    assert results["%s is missing" % missing] == hardening.FAIL


def test_a_declared_but_inactive_remap_fails(server):
    # The whole point of this check: the config says one thing and the daemon
    # is doing another.
    server.add_file(DAEMON, '{"userns-remap": "default", "no-new-privileges": true}')
    server.install("docker", "/var/lib/docker")
    results = hardening.check_docker_hardening(server)

    assert hardening.count_failures(results) == 1


def test_no_daemon_config_is_skipped(server):
    assert only(hardening.check_docker_hardening(server)).outcome == hardening.SKIP


def test_an_unparseable_daemon_config_fails_both_keys(server):
    server.add_file(DAEMON, "this is not json")
    results = hardening.check_docker_hardening(server)

    assert hardening.count_failures(results) == 2


###########################################################
# Rate limiting
###########################################################

GOOD_NGINX = ("limit_req_zone $binary_remote_addr zone=mylimit:10m rate=5r/s;\n"
              "    limit_req zone=mylimit burst=20 nodelay;\n"
              "server_tokens off;\n")


def test_a_configured_and_used_zone_passes(server):
    server.install("nginx", GOOD_NGINX)

    assert all_passed(hardening.check_rate_limiting(server))


def test_a_zone_that_nothing_consumes_fails(server):
    # This was the real defect: defined, never applied, nothing limited.
    server.install("nginx", "limit_req_zone $binary_remote_addr zone=mylimit:10m;\n"
                            "server_tokens off;\n")
    results = outcomes(hardening.check_rate_limiting(server))

    assert results[
        "limit_req is missing - the zone is defined but never applied"] == hardening.FAIL


def test_server_tokens_on_fails(server):
    server.install("nginx", GOOD_NGINX.replace("server_tokens off", "server_tokens on"))
    results = outcomes(hardening.check_rate_limiting(server))

    assert results["server_tokens is not off"] == hardening.FAIL


def test_no_nginx_is_skipped(server):
    assert only(hardening.check_rate_limiting(server)).outcome == hardening.SKIP


def test_a_burst_that_gets_refused_passes(server):
    server.install("nginx", GOOD_NGINX)
    server.install("curl", "503")

    assert all_passed(hardening.check_rate_limiting(server, domain = "joybox.test"))


def test_a_burst_that_is_never_refused_fails(server):
    # Configuration is not proof that it works.
    server.install("nginx", GOOD_NGINX)
    server.install("curl", "200")
    results = hardening.check_rate_limiting(server, domain = "joybox.test")

    assert hardening.count_failures(results) == 1


def test_no_domain_runs_no_burst(server):
    server.install("nginx", GOOD_NGINX)
    server.install("curl", "200")
    hardening.check_rate_limiting(server)

    assert not any(cmd[0] == "curl" for cmd in server.ran)


def test_the_burst_stays_on_the_machine_being_checked(server):
    # A test guest using the real domain would otherwise burst production.
    server.install("nginx", GOOD_NGINX)
    server.install("curl", "503")
    hardening.check_rate_limiting(server, domain = "example.com", burst_size = 1)

    burst = [cmd for cmd in server.ran if cmd[0] == "curl"][0]
    assert burst[burst.index("--resolve") + 1] == "example.com:443:127.0.0.1"
    assert burst[-1] == "https://example.com/"


def test_the_burst_size_is_honoured(server):
    server.install("nginx", GOOD_NGINX)
    server.install("curl", "200")
    hardening.check_rate_limiting(server, domain = "joybox.test", burst_size = 5)

    assert len([cmd for cmd in server.ran if cmd[0] == "curl"]) == 5


###########################################################
# Unattended upgrades
###########################################################

UNATTENDED = "/etc/apt/apt.conf.d/52-joybox-unattended"


def test_a_complete_unattended_config_passes(server):
    server.add_file(UNATTENDED, 'Unattended-Upgrade::Automatic-Reboot "true";\n')

    assert all_passed(hardening.check_unattended_upgrades(server))


def test_a_missing_unattended_config_fails(server):
    # Not a skip: the setup is supposed to have written it.
    assert only(hardening.check_unattended_upgrades(server)).outcome == hardening.FAIL


def test_no_automatic_reboot_fails(server):
    server.add_file(UNATTENDED, 'APT::Periodic::Unattended-Upgrade "1";\n')
    results = hardening.check_unattended_upgrades(server)

    assert hardening.count_failures(results) == 1


###########################################################
# The whole run
###########################################################

def test_a_hardened_server_passes_everything():
    results = hardening.verify_hardening(hardened_server(), domain = "joybox.test")

    assert hardening.count_failures(results) == 0
    assert results


def test_every_check_contributes_a_section():
    results = hardening.verify_hardening(hardened_server(), domain = "joybox.test")
    sections = {result.section for result in results}

    assert len(sections) == len(hardening.CHECKS)


def test_a_bare_server_fails_only_what_it_should():
    # Nothing installed: the checks skip rather than failing, except the
    # unattended config, which the setup was supposed to write.
    results = hardening.verify_hardening(FakeServer())

    assert hardening.count_failures(results) == 1


def test_one_bad_setting_fails_the_run():
    server = hardened_server()
    server.install("sshd", "passwordauthentication yes\npermitrootlogin yes\n")
    results = hardening.verify_hardening(server, domain = "joybox.test")

    assert hardening.count_failures(results) == 2


def test_the_results_are_reported_in_check_order():
    results = hardening.verify_hardening(hardened_server(), domain = "joybox.test")
    seen = []
    for result in results:
        if result.section not in seen:
            seen.append(result.section)

    assert seen[0] == "Container port bindings"
    assert seen[-1] == "Unattended upgrades"


def test_the_report_groups_by_section():
    results = hardening.verify_hardening(hardened_server(), domain = "joybox.test")
    report = hardening.format_results(results)

    assert "== Firewall" in report
    assert "== sshd" in report


def test_the_report_shows_the_detail_lines():
    results = hardening.verify_hardening(hardened_server(), domain = "joybox.test")

    assert "22/tcp ALLOW Anywhere" in hardening.format_results(results)
