# Imports
import os
import subprocess

# Third-party imports
import pytest

# Local imports
from bootstrap_helpers import output

pytestmark = pytest.mark.requires_binary("bash", "unshare", "openssl")


###########################################################
# Certbot manager
#
# The account runs this as root without a password, so its arguments are the
# account's to choose. Every refusal here happens before anything is written,
# which is what makes it safe to run unprivileged.
###########################################################

@pytest.fixture
def run_manager(shell_traced_env):
    def run(bootstrap_dir, *arguments):
        script = os.path.join(bootstrap_dir, "managers", "manager_certbot.sh")
        env = shell_traced_env(dict(os.environ, SUDO_UID = str(os.getuid())))
        return subprocess.run(["bash", script] + list(arguments),
                              capture_output = True, text = True, env = env, check = False)
    return run


@pytest.mark.parametrize("domain", ["../../etc", "example.com/../../etc", "-rf", "localhost", ".example.com"])
def test_install_refuses_a_name_that_is_not_a_domain(run_manager, bootstrap_dir, tmp_path, domain):
    result = run_manager(bootstrap_dir, "install_pair", domain, str(tmp_path / "a"), str(tmp_path / "b"))

    assert result.returncode != 0
    assert "is not a domain name" in result.stdout


def test_install_refuses_a_file_the_caller_does_not_own(run_manager, bootstrap_dir, tmp_path):
    # Otherwise it could copy out a file only root can read.
    key = tmp_path / "privkey.pem"
    key.write_text("KEY")
    result = run_manager(bootstrap_dir, "install_pair", "example.com", "/etc/passwd", str(key))

    assert result.returncode != 0
    assert "not a regular file owned by the caller" in result.stdout


def test_install_refuses_a_link(run_manager, bootstrap_dir, tmp_path):
    link = tmp_path / "fullchain.pem"
    link.symlink_to("/etc/passwd")
    key = tmp_path / "privkey.pem"
    key.write_text("KEY")
    result = run_manager(bootstrap_dir, "install_pair", "example.com", str(link), str(key))

    assert result.returncode != 0
    assert "not a regular file owned by the caller" in result.stdout


def test_install_refuses_something_that_is_not_a_certificate(run_manager, bootstrap_dir, tmp_path):
    cert = tmp_path / "fullchain.pem"
    cert.write_text("not a certificate")
    key = tmp_path / "privkey.pem"
    key.write_text("not a key")
    result = run_manager(bootstrap_dir, "install_pair", "example.com", str(cert), str(key))

    assert result.returncode != 0
    assert "is not a certificate" in result.stdout


def test_selfsign_refuses_a_bad_name_anywhere_in_the_list(run_manager, bootstrap_dir):
    result = run_manager(bootstrap_dir, "selfsign", "example.com", "www.example.com", "../../etc")

    assert result.returncode != 0
    assert "is not a domain name" in result.stdout


def test_selfsign_locks_down_the_private_key(run_manager, bootstrap_dir):
    with open(os.path.join(bootstrap_dir, "managers", "manager_certbot.sh"), "r", encoding = "utf-8") as script:
        body = script.read().split("selfsign_cert() {", 1)[1].split("\n}\n", 1)[0]

    assert 'chmod 600 "$CERT_DIR/privkey.pem"' in body
    assert 'chmod 644 "$CERT_DIR/fullchain.pem"' in body


###########################################################
# Sandboxed runs
###########################################################

SCRIPT = "Bootstrap/managers/manager_certbot.sh"
LIVE = "/etc/letsencrypt/live/example.com"
ARCHIVE = "/etc/letsencrypt/archive/example.com"
NUMFMT = 'exec /usr/bin/numfmt "$@"\n'


@pytest.fixture(scope = "module")
def pair(tmp_path_factory):
    folder = tmp_path_factory.mktemp("pair")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-days", "30", "-subj", "/CN=example.com",
        "-keyout", str(folder / "privkey.pem"), "-out", str(folder / "fullchain.pem")],
        capture_output = True, check = True)
    return (folder / "fullchain.pem").read_text(), (folder / "privkey.pem").read_text()


@pytest.fixture
def server(shell_sandbox):
    shell_sandbox.stub("numfmt", script = NUMFMT)
    return shell_sandbox


def place(server, directory, pair, fullchain = "fullchain.pem", privkey = "privkey.pem"):
    server.write("%s/%s" % (directory, fullchain), pair[0])
    server.write("%s/%s" % (directory, privkey), pair[1])


###########################################################
# Arguments
###########################################################

@pytest.mark.parametrize("arguments, message", [
    ([], None),
    (["register", "a@example.com"], "register requires email"),
    (["install_pair", "example.com"], "install_pair requires domain"),
    (["selfsign"], "selfsign requires at least one domain"),
    (["copy_certs", "example.com"], "copy_certs requires domain"),
    (["export_keystore", "example.com", "/tmp/k", "pw"], "export_keystore requires domain"),
    (["check"], "check requires domain name"),
    (["frobnicate"], "Invalid operation 'frobnicate'"),
])
def test_bad_arguments_print_the_usage(server, arguments, message):
    result = server.run(SCRIPT, *arguments)

    assert result.returncode == 1
    assert "Usage:" in result.stdout
    if message:
        assert message in result.stdout


###########################################################
# Register and renew
###########################################################

def test_register_asks_certbot_for_every_domain(server):
    result = server.run(SCRIPT, "register", "a@example.com", "example.com", "www.example.com")

    assert result.returncode == 0, output(result)
    assert server.calls("certbot") == [[
        "certonly", "--nginx", "--non-interactive", "--expand", "--agree-tos", "--email", "a@example.com",
        "-d", "example.com", "-d", "www.example.com"]]


def test_renew_renews_quietly(server):
    result = server.run(SCRIPT, "renew")

    assert result.returncode == 0, output(result)
    assert server.calls("certbot") == [["renew", "--non-interactive", "--quiet"]]


###########################################################
# Install a staged pair
###########################################################

def test_install_places_the_pair_with_tight_permissions(server, pair):
    place(server, "/tmp/staged", pair)

    result = server.run(SCRIPT, "install_pair", "example.com", "/tmp/staged/fullchain.pem", "/tmp/staged/privkey.pem")

    assert result.returncode == 0, output(result)
    assert server.read(LIVE + "/fullchain.pem") == pair[0]
    assert os.stat(server.host_path(LIVE + "/privkey.pem")).st_mode & 0o777 == 0o600
    assert os.stat(server.host_path(LIVE + "/fullchain.pem")).st_mode & 0o777 == 0o644


def test_install_refuses_a_file_another_user_staged(server, pair):
    place(server, "/tmp/staged", pair)

    result = server.run(SCRIPT, "install_pair", "example.com", "/tmp/staged/fullchain.pem", "/tmp/staged/privkey.pem",
                        env = {"SUDO_UID": "1000"})

    assert result.returncode == 1
    assert "not a regular file owned by the caller" in result.stdout
    assert not server.exists(LIVE)


def test_install_refuses_something_that_is_not_a_key(server, pair):
    server.write("/tmp/staged/fullchain.pem", pair[0])
    server.write("/tmp/staged/privkey.pem", "not a key")

    result = server.run(SCRIPT, "install_pair", "example.com", "/tmp/staged/fullchain.pem", "/tmp/staged/privkey.pem")

    assert result.returncode == 1
    assert "is not a private key" in result.stdout
    assert not server.exists(LIVE)


###########################################################
# Self-signed
###########################################################

def test_selfsign_covers_every_name(server):
    result = server.run(SCRIPT, "selfsign", "example.com", "www.example.com")

    assert result.returncode == 0, output(result)
    text = subprocess.run(["openssl", "x509", "-in", server.host_path(LIVE + "/fullchain.pem"), "-noout", "-text"],
                          capture_output = True, text = True, check = True).stdout
    assert "DNS:example.com, DNS:www.example.com" in text
    assert os.stat(server.host_path(LIVE + "/privkey.pem")).st_mode & 0o777 == 0o600


###########################################################
# Copy
###########################################################

def test_copy_takes_the_live_pair(server, pair):
    place(server, LIVE, pair)

    result = server.run(SCRIPT, "copy_certs", "example.com", "/srv/certs")

    assert result.returncode == 0, output(result)
    assert "copied successfully" in result.stdout
    assert server.read("/srv/certs/fullchain.pem") == pair[0]
    assert os.stat(server.host_path("/srv/certs/privkey.pem")).st_mode & 0o777 == 0o600
    assert "subject=CN" in result.stdout


def test_copy_falls_back_to_the_newest_archived_pair(server, pair):
    os.makedirs(server.host_path(LIVE))
    server.write(ARCHIVE + "/fullchain1.pem", "old")
    server.write(ARCHIVE + "/privkey1.pem", "old")
    place(server, ARCHIVE, pair, "fullchain2.pem", "privkey2.pem")

    result = server.run(SCRIPT, "copy_certs", "example.com", "/srv/certs")

    assert result.returncode == 0, output(result)
    assert "copied successfully from archive" in result.stdout
    assert server.read("/srv/certs/privkey.pem") == pair[1]


def test_copy_without_a_certificate_lists_the_others(server, pair):
    place(server, "/etc/letsencrypt/live/other.example.com", pair)

    result = server.run(SCRIPT, "copy_certs", "example.com", "/srv/certs")

    assert result.returncode == 1
    assert "does not exist" in result.stdout
    assert result.stdout.splitlines()[-1] == "other.example.com"


def test_copy_without_any_certificate_says_so(server):
    result = server.run(SCRIPT, "copy_certs", "example.com", "/srv/certs")

    assert result.returncode == 1
    assert "No certificates found" in result.stdout


def test_copy_without_an_archive_fails(server):
    os.makedirs(server.host_path(LIVE))

    result = server.run(SCRIPT, "copy_certs", "example.com", "/srv/certs")

    assert result.returncode == 1
    assert "Archive directory %s does not exist" % ARCHIVE in result.stdout


def test_copy_from_an_empty_archive_fails(server):
    os.makedirs(server.host_path(LIVE))
    os.makedirs(server.host_path(ARCHIVE))

    result = server.run(SCRIPT, "copy_certs", "example.com", "/srv/certs")

    assert result.returncode == 1
    assert "Could not find certificate files" in result.stdout


###########################################################
# Export a keystore
###########################################################

def export(server, *arguments):
    return server.run(SCRIPT, "export_keystore", "example.com", "/srv/app/keystore", "secret", "app", *arguments)


def test_export_writes_a_pkcs12_keystore(server, pair):
    place(server, LIVE, pair)

    result = export(server)

    assert result.returncode == 0, output(result)
    assert "Owner: (unchanged)" in result.stdout
    assert os.stat(server.host_path("/srv/app/keystore")).st_mode & 0o777 == 0o600
    assert server.calls("chown") == []
    check = subprocess.run(["openssl", "pkcs12", "-in", server.host_path("/srv/app/keystore"), "-nokeys",
                            "-password", "pass:secret"], capture_output = True, text = True, check = False)
    assert check.returncode == 0, check.stderr


def test_export_names_the_format_when_openssl_cannot_describe_the_keystore(server, pair):
    place(server, LIVE, pair)
    server.stub("openssl", script = 'case " $* " in *" -info "*) exit 1 ;; esac\nexec "${0%/*}/../tools/openssl" "$@"\n')

    result = export(server)

    assert result.returncode == 0, output(result)
    assert "Format: PKCS12" in result.stdout


def test_export_sets_the_permissions_and_owner_asked_for(server, pair):
    place(server, LIVE, pair)

    result = export(server, "p12", "640", "www-data:www-data")

    assert result.returncode == 0, output(result)
    assert os.stat(server.host_path("/srv/app/keystore")).st_mode & 0o777 == 0o640
    assert server.calls("chown") == [["www-data:www-data", "/srv/app/keystore"]]


def test_export_converts_to_jks_with_keytool(server, pair):
    place(server, LIVE, pair)
    server.stub("keytool", script = '[ "$1" = "-importkeystore" ] && : > "$9"\nexit 0\n')

    result = export(server, "jks")

    assert result.returncode == 0, output(result)
    imports, listing = server.calls("keytool")
    assert imports[:3] == ["-importkeystore", "-srckeystore", imports[2]]
    assert imports[2].endswith(".p12") and not server.exists(imports[2])
    assert "-destkeystore" in imports and "JKS" in imports
    assert listing[:3] == ["-list", "-keystore", "/srv/app/keystore"]


def test_export_to_jks_without_keytool_fails_cleanly(server, pair):
    place(server, LIVE, pair)
    os.remove(os.path.join(server.stub_dir, "keytool"))

    result = export(server, "jks")

    assert result.returncode == 1
    assert "keytool not found" in result.stdout
    assert not [name for name in os.listdir(server.host_path("/tmp")) if name.endswith(".p12")]


def test_export_refuses_an_unknown_format(server, pair):
    place(server, LIVE, pair)

    result = export(server, "pem")

    assert result.returncode == 1
    assert "Invalid format 'pem'" in result.stdout
    assert not server.exists("/srv/app")


def test_export_falls_back_to_the_archive(server, pair):
    os.makedirs(server.host_path(LIVE))
    place(server, ARCHIVE, pair, "fullchain3.pem", "privkey3.pem")

    result = export(server)

    assert result.returncode == 0, output(result)
    assert "Found latest fullchain: %s/fullchain3.pem" % ARCHIVE in result.stdout


def test_export_without_a_certificate_lists_the_others(server):
    result = export(server)

    assert result.returncode == 1
    assert "No certificates found" in result.stdout


def test_export_without_an_archive_fails(server):
    os.makedirs(server.host_path(LIVE))

    result = export(server)

    assert result.returncode == 1
    assert "Archive directory %s does not exist" % ARCHIVE in result.stdout


def test_export_from_an_empty_archive_fails(server):
    os.makedirs(server.host_path(LIVE))
    os.makedirs(server.host_path(ARCHIVE))

    result = export(server)

    assert result.returncode == 1
    assert "Could not find certificate files" in result.stdout


###########################################################
# List and check
###########################################################

def test_list_shows_each_domain_and_its_expiry(server, pair):
    place(server, LIVE, pair)
    server.write("/etc/letsencrypt/live/broken.example.com/fullchain.pem", "garbage")
    os.makedirs(server.host_path("/etc/letsencrypt/live/empty.example.com"))
    server.write("/etc/letsencrypt/live/README", "readme")

    result = server.run(SCRIPT, "list")

    assert result.returncode == 0, output(result)
    assert "Domain: example.com\n    Expires: " in result.stdout
    assert "Domain: broken.example.com\n    Expires: unreadable certificate" in result.stdout
    assert "Domain: empty.example.com\n" in result.stdout
    assert "README" not in result.stdout


def test_list_without_letsencrypt_says_so(server):
    result = server.run(SCRIPT, "list")

    assert result.returncode == 0, output(result)
    assert "No certificates found" in result.stdout


def test_check_prints_the_certificate(server, pair):
    place(server, LIVE, pair)

    result = server.run(SCRIPT, "check", "example.com")

    assert result.returncode == 0, output(result)
    assert "Subject: CN = example.com" in result.stdout
    assert "Not After" in result.stdout


def test_check_refuses_a_name_that_is_not_a_domain(server):
    result = server.run(SCRIPT, "check", "../../etc")

    assert result.returncode == 1
    assert "is not a domain name" in result.stdout


def test_check_wants_both_halves_of_the_pair(server, pair):
    server.write(LIVE + "/fullchain.pem", pair[0])

    result = server.run(SCRIPT, "check", "example.com")

    assert result.returncode == 1
    assert "does not exist" in result.stdout
