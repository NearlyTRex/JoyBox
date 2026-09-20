# Imports
import os
import re

# Third-party imports
import pytest

# Local imports
from joybox import hardening


###########################################################
# Day-0 shell against the hardening checks
#
# common.sh writes the configuration and Shared/joybox/hardening.py reads it
# back from a live server. Nothing links the two at runtime - the shell has to
# run on a bare target before the repo exists - so a rename on either side
# would only surface as a verification failure against a real box. These feed
# what the shell writes through the parsers that will read it.
###########################################################

@pytest.fixture(scope = "module")
def common_sh(bootstrap_dir):
    with open(os.path.join(bootstrap_dir, "scripts", "common.sh"), "r") as script:
        return script.read()


# The body of a "cat > <path> <<EOF ... EOF" block, with shell escaping undone
def read_heredoc(contents, path):
    pattern = re.compile(
        r"cat\s+>\s+%s\s+<<'?EOF'?\n(.*?)\nEOF\n" % re.escape(path), re.DOTALL)
    match = pattern.search(contents)
    assert match, "common.sh no longer writes %s with a heredoc" % path
    return match.group(1).replace("\\$", "$").replace("\\`", "`")


###########################################################
# sshd
###########################################################

def test_the_sshd_dropin_is_written(common_sh):
    body = read_heredoc(common_sh, "/etc/ssh/sshd_config.d/99-joybox.conf")

    assert body.strip()


def test_the_sshd_dropin_satisfies_the_sshd_check(common_sh):
    # sshd -T reports one setting per line, the same shape as the drop-in
    body = read_heredoc(common_sh, "/etc/ssh/sshd_config.d/99-joybox.conf")

    settings = hardening.parse_sshd_settings(body)

    assert settings.get("passwordauthentication") == "no"
    assert settings.get("permitrootlogin") in ("no", "prohibit-password")


def test_the_sshd_dropin_keeps_key_auth_on(common_sh):
    # Turning password auth off without this is a lockout
    body = read_heredoc(common_sh, "/etc/ssh/sshd_config.d/99-joybox.conf")

    settings = hardening.parse_sshd_settings(body)

    assert settings.get("pubkeyauthentication") == "yes"


###########################################################
# Docker
###########################################################

def test_the_daemon_config_declares_every_checked_key(common_sh):
    body = read_heredoc(common_sh, "/etc/docker/daemon.json")

    keys = hardening.parse_daemon_keys(body)

    assert "userns-remap" in keys
    assert "no-new-privileges" in keys


def test_the_daemon_config_is_valid_json(common_sh):
    # parse_daemon_keys swallows a parse error and reports no keys, so a broken
    # heredoc would read as missing hardening rather than as a syntax error
    body = read_heredoc(common_sh, "/etc/docker/daemon.json")

    assert hardening.parse_daemon_keys(body)


###########################################################
# Unattended upgrades
###########################################################

def test_the_unattended_config_satisfies_the_upgrade_check(common_sh):
    body = read_heredoc(common_sh, "/etc/apt/apt.conf.d/52-joybox-unattended")

    state = hardening.parse_unattended_upgrades(body)

    assert state["present"]
    assert state["automatic_reboot"]


###########################################################
# Rate limiting
#
# The zone and the directive consuming it are written by two different
# functions into two different snippets. nginx -T sees them together, so the
# check does too.
###########################################################

def test_the_nginx_snippets_satisfy_the_rate_limit_check(common_sh):
    zone = read_heredoc(common_sh, "/etc/nginx/snippets/rate-limit.conf")
    params = read_heredoc(common_sh, "/etc/nginx/snippets/ssl-params.conf")

    state = hardening.parse_nginx_rate_limiting(zone + "\n" + params)

    assert state["zone_defined"]
    assert state["zone_used"]
    assert state["tokens_off"]


def test_the_directive_names_the_zone_that_is_defined(common_sh):
    # limit_req naming a zone that limit_req_zone never declared fails at
    # nginx -t, which the parsers cannot see
    zone = read_heredoc(common_sh, "/etc/nginx/snippets/rate-limit.conf")
    params = read_heredoc(common_sh, "/etc/nginx/snippets/ssl-params.conf")

    defined = set(re.findall(r"zone=(\w+):", zone))
    used = set(re.findall(r"limit_req\s+zone=(\w+)", params))

    assert used
    assert used <= defined


###########################################################
# fail2ban
###########################################################

def test_every_checked_jail_is_configured(common_sh):
    # The names check_fail2ban asks fail2ban-client about by default
    configured = set(re.findall(r"^\[([\w-]+)\]$", common_sh, re.MULTILINE))

    for jail in ["sshd", "nginx-http-auth"]:
        assert jail in configured, "common.sh configures no '%s' jail" % jail


def test_the_ssh_jail_reads_journald(common_sh):
    # The packaged jail watches /var/log/auth.log, which Ubuntu 24.04+ does not
    # have, and silently matches nothing
    body = read_heredoc(common_sh, "/etc/fail2ban/jail.d/sshd.conf")

    assert re.search(r"backend\s*=\s*systemd", body)
