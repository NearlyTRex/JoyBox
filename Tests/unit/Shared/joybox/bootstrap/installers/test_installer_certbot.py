# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox import serverinfo
from fakes import RecordingConnection


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


###########################################################
# Installed state
#
# The aptget component installs the certbot package as well, so the package
# being present must not stand in for an issued certificate.
###########################################################

def test_the_package_alone_is_not_installed(isolated_settings):
    connection = RecordingConnection(
        existing_paths = ["/usr/bin/certbot"],
        return_codes = {"manager_certbot.sh check": 1})

    assert not build_certbot(isolated_settings, connection, "mkcert").is_installed()


def test_an_issued_certificate_is_installed(isolated_settings):
    connection = RecordingConnection(existing_paths = ["/usr/bin/certbot"])
    certbot = build_certbot(isolated_settings, connection, "mkcert")

    assert certbot.is_installed()
    assert [certbot.cert_manager_tool, "check", "joybox.test"] in connection.commands


def test_only_remote_ubuntu_is_supported(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")

    assert certbot.get_supported_environments() == [constants.EnvironmentType.REMOTE_UBUNTU]


def test_no_package_is_not_installed(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")

    assert not certbot.is_installed()
    assert not recording_connection.ran("check")


###########################################################
# mkcert
#
# The certificate is signed on the workstation by its local CA; only the leaf
# and key travel to the target.
###########################################################

LOCAL_DIR = "/tmp/joybox-test"


class NoTemporaryDirectory(RecordingConnection):
    def make_temporary_directory(self):
        self._record("make_temporary_directory")
        return None


class StagingFails(RecordingConnection):
    def __init__(self, failing_method, **kwargs):
        super().__init__(**kwargs)
        self.failing_method = failing_method

    def make_directory(self, src, sudo = False):
        if self.failing_method == "make_directory":
            self._record("make_directory", src, sudo = sudo)
            return False
        return super().make_directory(src, sudo = sudo)

    def write_file(self, src, contents, sudo = False):
        if self.failing_method == "write_file":
            self._record("write_file", src, contents, sudo = sudo)
            return False
        return super().write_file(src, contents, sudo = sudo)


def use_local(monkeypatch, local):
    from joybox.bootstrap.installers import installer_certbot
    monkeypatch.setattr(installer_certbot.connection, "ConnectionLocal", lambda flags, options: local)


def mkcert_output(cert = "CERT", key = "KEY", **kwargs):
    return RecordingConnection(file_contents = {
        f"{LOCAL_DIR}/fullchain.pem": cert, f"{LOCAL_DIR}/privkey.pem": key}, **kwargs)


def test_mkcert_signs_locally_and_installs_the_pair(isolated_settings, recording_connection, monkeypatch):
    local = mkcert_output()
    use_local(monkeypatch, local)
    certbot = build_certbot(isolated_settings, recording_connection, "mkcert")

    assert certbot.install()
    assert local.ran("mkcert -cert-file", f"{LOCAL_DIR}/fullchain.pem", "joybox.test")
    assert set(certbot.fully_qualified_domains) <= set(local.commands[0])
    assert local.removed_paths == [LOCAL_DIR]
    assert recording_connection.written("fullchain.pem") == "CERT"
    assert recording_connection.ran("install_pair", "joybox.test")
    assert not recording_connection.ran("mkcert")


def test_mkcert_needs_a_local_temporary_directory(isolated_settings, recording_connection, monkeypatch):
    use_local(monkeypatch, NoTemporaryDirectory())
    certbot = build_certbot(isolated_settings, recording_connection, "mkcert")

    assert not certbot.install()
    assert not recording_connection.ran("install_pair")


def test_a_failed_mkcert_cleans_up_and_fails(isolated_settings, recording_connection, monkeypatch):
    local = mkcert_output(return_codes = {"mkcert": 1})
    use_local(monkeypatch, local)
    certbot = build_certbot(isolated_settings, recording_connection, "mkcert")

    assert not certbot.install()
    assert local.removed_paths == [LOCAL_DIR]
    assert not recording_connection.ran("install_pair")


def test_an_empty_mkcert_result_is_not_installed(isolated_settings, recording_connection, monkeypatch):
    use_local(monkeypatch, mkcert_output(key = ""))
    certbot = build_certbot(isolated_settings, recording_connection, "mkcert")

    assert not certbot.install_mkcert_cert()
    assert not recording_connection.ran("install_pair")


def test_an_unstageable_pair_is_not_installed(isolated_settings):
    for failing_method in ["make_directory", "write_file"]:
        connection = StagingFails(failing_method)
        certbot = build_certbot(isolated_settings, connection, "mkcert")

        assert not certbot.write_cert_pair("CERT", "KEY")
        assert not connection.ran("install_pair")


def test_a_failed_selfsign_stops_before_nginx(isolated_settings, recording_connection, monkeypatch):
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    monkeypatch.setattr(certbot, "install_selfsigned_cert", lambda: False)

    assert not certbot.install()
    assert not recording_connection.ran("restart")


def test_letsencrypt_uninstall_removes_the_renewal(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")
    certbot.uninstall()

    assert recording_connection.crontab_removed == [f"0 3 * * * {certbot.cert_manager_tool} renew"]
    assert recording_connection.ran("remove -y certbot")


def test_an_unwritable_default_entry_is_not_installed(isolated_settings, monkeypatch):
    connection = RecordingConnection()
    certbot = build_certbot(isolated_settings, connection, "selfsigned")
    monkeypatch.setattr(connection, "write_file", lambda src, contents, sudo = False: False)

    assert certbot.install()
    assert not connection.ran("install_conf")
    assert connection.ran("systemctl", "restart")
