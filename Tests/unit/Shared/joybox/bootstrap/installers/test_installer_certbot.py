# Imports
import pytest

# Local imports
import joybox.bootstrap.installers as installers
from joybox import serverinfo


###########################################################
# Certificate issuance modes
#
# Every app's nginx template hardcodes /etc/letsencrypt/live/<apex>/, so all
# three modes must land the certificate at that same path.
###########################################################

def build_certbot(settings, connection, tls_mode):
    settings.set_value("UserData.Servers", "server_0_tls_mode", tls_mode)
    return installers.Certbot(connection)


def test_cert_path_uses_the_apex_domain(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")
    assert certbot.get_cert_dir() == "/etc/letsencrypt/live/joybox.test"


def test_san_list_covers_apex_and_every_subdomain(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")

    assert certbot.fully_qualified_domains[0] == "joybox.test"
    for subdomain in ["www", "admin", "cloud", "tools", "tasks", "audio", "music", "aim"]:
        assert f"{subdomain}.joybox.test" in certbot.fully_qualified_domains


def test_san_list_has_no_empty_entries(isolated_settings, recording_connection):
    # A bare ".joybox.test" makes certbot reject the whole batch.
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")
    for name in certbot.fully_qualified_domains:
        assert name and not name.startswith("."), f"malformed SAN: {name!r}"


def test_letsencrypt_mode_registers_and_schedules_renewal(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")
    assert certbot.install() is True

    assert recording_connection.ran("register", "joybox.test")
    assert recording_connection.crontab_added, "letsencrypt mode must schedule renewal"


def test_letsencrypt_mode_refuses_without_a_contact(isolated_settings, recording_connection):
    isolated_settings.set_value("UserData.Servers", "server_0_domain_contact", "")
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")

    assert certbot.install() is False
    assert not recording_connection.ran("register")


def test_local_modes_need_no_contact(isolated_settings, recording_connection):
    isolated_settings.set_value("UserData.Servers", "server_0_domain_contact", "")
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")

    assert certbot.install() is True


def test_selfsigned_mode_never_contacts_lets_encrypt(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    assert certbot.install() is True

    assert not recording_connection.ran("register"), \
        "selfsigned mode must not run the ACME registration"
    assert not recording_connection.crontab_added, \
        "there is nothing to renew, so no cron entry belongs here"
    assert recording_connection.ran("selfsign", "joybox.test")


def selfsign_command(connection):
    return [cmd for cmd in connection.commands if "selfsign" in cmd][0]


def test_selfsigned_is_made_for_the_apex_directory(isolated_settings, recording_connection):
    # The manager writes to /etc/letsencrypt/live/<first name>.
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    certbot.install()

    command = selfsign_command(recording_connection)
    assert command[command.index("selfsign") + 1] == "joybox.test"


def test_selfsigned_covers_every_name_in_the_san_list(isolated_settings, recording_connection):
    # A cert covering only the apex makes every subdomain warn.
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    certbot.install()

    command = selfsign_command(recording_connection)
    assert set(certbot.fully_qualified_domains) <= set(command)


def privileged_programs(connection):
    return {call[1][0][0] for call in connection.calls
            if call[0].startswith("run_") and call[2].get("sudo")}


def test_selfsigned_needs_only_granted_sudo(isolated_settings, recording_connection):
    # The account's sudo covers apt-get and the manager scripts, nothing else.
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    certbot.install()

    assert privileged_programs(recording_connection) <= {
        certbot.aptget_tool, certbot.cert_manager_tool, certbot.nginx_manager_tool}


###########################################################
# Installing a certificate made elsewhere
###########################################################

def test_a_pair_is_installed_by_the_manager(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "mkcert")

    assert certbot.write_cert_pair("CERT", "KEY") is True
    install = [cmd for cmd in recording_connection.commands if "install_pair" in cmd][0]
    assert install[install.index("install_pair") + 1] == "joybox.test"
    assert privileged_programs(recording_connection) == {certbot.cert_manager_tool}


def test_a_pair_is_staged_where_only_the_account_can_read_it(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "mkcert")
    certbot.write_cert_pair("CERT", "KEY")

    staging_dir = recording_connection.made_directories[0]
    assert (staging_dir, "700") in recording_connection.permissions
    assert recording_connection.written("privkey.pem") == "KEY"
    assert all(path.startswith(staging_dir) for path, _ in recording_connection.write_log)


def test_a_staged_pair_is_removed(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "mkcert")
    certbot.write_cert_pair("CERT", "KEY")

    assert recording_connection.made_directories[0] in recording_connection.removed_paths


def test_unknown_mode_fails_rather_than_guessing(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "nonsense")

    assert certbot.install() is False
    assert not recording_connection.ran("register")
    assert not recording_connection.ran("selfsign")


def test_mode_defaults_to_letsencrypt(isolated_settings, recording_connection):
    # A server entry that names no mode gets a real certificate.
    isolated_settings.set_value("UserData.Servers", "server_1_domain_name", "example.com")
    serverinfo.select_server(1)
    certbot = installers.Certbot(recording_connection)

    assert certbot.tls_mode == "letsencrypt"


def test_certificate_settings_come_from_the_selected_server(isolated_settings, recording_connection):
    # A test VM alongside a real server must not change the real one's certificate.
    isolated_settings.set_value("UserData.Servers", "server_0_tls_mode", "letsencrypt")
    isolated_settings.set_value("UserData.Servers", "server_1_domain_name", "example.com")
    isolated_settings.set_value("UserData.Servers", "server_1_domain_contact", "vm@example.com")
    isolated_settings.set_value("UserData.Servers", "server_1_tls_mode", "mkcert")

    serverinfo.select_server(1)
    vm = installers.Certbot(recording_connection)
    serverinfo.select_server(0)
    real = installers.Certbot(recording_connection)

    assert (vm.domain_name, vm.domain_contact, vm.tls_mode) == ("example.com", "vm@example.com", "mkcert")
    assert (real.domain_name, real.domain_contact, real.tls_mode) == ("joybox.test", "nobody@joybox.test", "letsencrypt")


def test_uninstall_only_removes_renewal_in_letsencrypt_mode(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    certbot.uninstall()

    assert not recording_connection.crontab_removed
