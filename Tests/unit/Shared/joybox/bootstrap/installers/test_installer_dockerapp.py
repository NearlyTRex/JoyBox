# Imports
import subprocess

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.installers as installers
import joybox.bootstrap.constants as constants
import joybox.bootstrap.packages as packages
from joybox import runoptions
from joybox.bootstrap.installers import installer_dockerapp
from fakes import RecordingConnection


###########################################################
# Backup and restore script generation
#
# Shell built by string concatenation and handed to a remote bash. An unbalanced
# quote here is a failed backup discovered at restore time.
###########################################################

@pytest.fixture
def wordpress(isolated_settings, recording_connection):
    settings = isolated_settings
    settings.set_value("UserData.Wordpress", "wordpress_db_pass", "dbpass")
    settings.set_value("UserData.Wordpress", "wordpress_db_root_pass", "rootpass")
    settings.set_value("UserData.Wordpress", "wordpress_admin_pass", "adminpass")
    settings.set_value("UserData.Wordpress", "wordpress_admin_email", "a@joybox.test")
    return installers.Wordpress(recording_connection)


def assert_valid_shell(script, tmp_path, label):
    path = tmp_path / f"{label}.sh"
    path.write_text(script)
    result = subprocess.run(["bash", "-n", str(path)], capture_output = True, text = True, check = False)
    assert result.returncode == 0, f"{label} is not valid shell:\n{result.stderr}"


def test_backup_script_is_valid_shell(wordpress, tmp_path):
    assert_valid_shell(wordpress.build_backup_script(), tmp_path, "backup")


def test_restore_script_is_valid_shell(wordpress, tmp_path):
    assert_valid_shell(wordpress.build_restore_script("latest"), tmp_path, "restore")


def test_backup_is_plain_gzip_without_a_recipient(wordpress, isolated_settings):
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", "")
    script = wordpress.build_backup_script()

    assert "gzip -9" in script
    assert "age -r" not in script

    # The checksum step names *.age in both modes, so assert on archive names.
    assert ".gz.age" not in script
    assert '> "$DEST/db.sql.gz"' in script


def test_backup_encrypts_when_a_recipient_is_set(wordpress, isolated_settings):
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", "age1example")
    script = wordpress.build_backup_script()

    assert "age -r age1example" in script
    assert 'db.sql.gz.age' in script
    assert 'wp_data.tar.gz.age' in script


def test_backup_fails_loudly_when_age_is_missing(wordpress, isolated_settings):
    # Writing plaintext because the binary is absent would be worse than failing.
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", "age1example")
    script = wordpress.build_backup_script()

    assert "command -v age" in script
    assert "exit 1" in script


def test_checksums_cover_encrypted_artifacts(wordpress, isolated_settings):
    # Matching only *.gz would leave an encrypted backup with empty checksums.
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", "age1example")
    script = wordpress.build_backup_script()

    assert "SHA256SUMS" in script
    assert "*.age" in script


def test_backup_publishes_atomically(wordpress):
    # A half-written backup must never be mistaken for a finished one.
    script = wordpress.build_backup_script()
    assert ".partial" in script
    assert 'mv "$DEST"' in script


def test_restore_reads_plain_archives_when_unencrypted(wordpress):
    script = wordpress.build_restore_script("latest")

    # Plain gzip fallback keeps pre-encryption backups restorable.
    assert "archive_stream" in script
    assert 'gzip -dc "$SRC/$1"' in script


def test_restore_refuses_encrypted_archives_without_an_identity(wordpress):
    script = wordpress.build_restore_script("latest")

    assert "backup_age_identity is not set" in script


def test_restore_uses_the_identity_when_given(wordpress):
    script = wordpress.build_restore_script("latest", "/dev/shm/key")

    assert "AGE_IDENTITY=/dev/shm/key" in script
    assert 'age -d -i "$AGE_IDENTITY"' in script


def test_restore_verifies_checksums_before_touching_data(wordpress):
    script = wordpress.build_restore_script("latest")

    # Match the call form, not the definition emitted above it.
    checksum_index = script.index("sha256sum -c SHA256SUMS")
    extract_index = script.index('archive_stream "')
    assert checksum_index < extract_index, \
        "restore must verify checksums before it starts overwriting live data"


def test_components_without_backup_data_do_nothing(isolated_settings, recording_connection):
    # Jenkins deliberately declares no backup items: jenkins_home_dir points at
    # /mnt/repositories, which holds every git repo on the box.
    isolated_settings.set_value("UserData.Jenkins", "jenkins_home_dir", "/mnt/repositories")
    jenkins = installers.Jenkins(recording_connection)

    assert jenkins.has_backup_items() is False
    assert jenkins.backup() is True
    assert recording_connection.commands == []


###########################################################
# Installed state
#
# Installed means every install step finished (the marker) and the app is
# still up (running, healthy containers); either alone is not enough.
###########################################################

HEALTHY = ("wordpress-db-1\trunning\tUp 5 minutes (healthy)\n"
           "wordpress-wordpress-1\trunning\tUp 4 minutes (healthy)\n"
           "navidrome-1\texited\tExited (1) 2 hours ago\n")


def build_with_containers(isolated_settings, listing, marked = True):
    connection = RecordingConnection(command_output = {"docker ps -a": listing})
    wordpress = installers.Wordpress(connection)
    if marked:
        connection.existing_paths.add(wordpress.get_install_marker())
    return wordpress


def test_no_containers_is_not_installed(isolated_settings):
    assert not build_with_containers(isolated_settings, "").is_installed()


def test_running_healthy_containers_are_installed(isolated_settings):
    assert build_with_containers(isolated_settings, HEALTHY).is_installed()


def test_healthy_containers_without_the_marker_are_not_installed(isolated_settings):
    assert not build_with_containers(isolated_settings, HEALTHY, marked = False).is_installed()


def test_an_unhealthy_container_is_not_installed(isolated_settings):
    listing = ("wordpress-db-1\trunning\tUp 5 minutes (unhealthy)\n"
               "wordpress-wordpress-1\tcreated\tCreated\n")
    assert not build_with_containers(isolated_settings, listing).is_installed()


def test_a_stopped_container_is_not_installed(isolated_settings):
    listing = ("wordpress-db-1\trunning\tUp 5 minutes (healthy)\n"
               "wordpress-wordpress-1\texited\tExited (0) 1 minute ago\n")
    assert not build_with_containers(isolated_settings, listing).is_installed()


def test_a_finished_install_writes_the_marker(wordpress, recording_connection, monkeypatch):
    monkeypatch.setattr(wordpress, "post_install", lambda: True)

    assert wordpress.install()
    assert wordpress.get_install_marker() in recording_connection.written_files


def test_a_failed_post_install_leaves_no_marker(wordpress, recording_connection, monkeypatch):
    monkeypatch.setattr(wordpress, "post_install", lambda: False)

    assert not wordpress.install()
    assert wordpress.get_install_marker() not in recording_connection.written_files
    assert wordpress.get_install_marker() in recording_connection.removed_paths


###########################################################
# Generic app
#
# A bare DockerAppInstaller subclass exercises the skeleton without any one
# app's templates or settings.
###########################################################

DEMO_RUNNING = "demo-app-1\trunning\tUp 1 minute\n"
DEMO_KEY = "AGE-SECRET-KEY-DEMO"


class DemoApp(installer_dockerapp.DockerAppInstaller):
    def __init__(self, connection, flags = runoptions.RunFlags(verbose = False)):
        super().__init__(connection, flags)
        self.app_name = "demo"
        self.app_subdirs = ["data", "config"]
        self.docker_compose_template = "services: {}\n"
        self.env_template = "DOMAIN={domain}\n"
        self.env_values = {"domain": "joybox.test"}
        self.nginx_config_values = {"subdomain": "demo", "domain": "joybox.test", "port_http": "8080"}
        self.required_settings = ["domain", "port_http"]
        self.nginx_ports = ["9000"]


class FailingWrites(RecordingConnection):
    def __init__(self, failing_fragment, **kwargs):
        super().__init__(**kwargs)
        self.failing_fragment = failing_fragment

    def write_file(self, src, contents, sudo = False):
        if self.failing_fragment in src:
            self._record("write_file", src, contents, sudo = sudo)
            return False
        return super().write_file(src, contents, sudo = sudo)


def build_demo(connection = None, installed = False, flags = None, **items):
    if connection is None:
        connection = RecordingConnection(command_output = {"docker ps -a": DEMO_RUNNING})
    app = DemoApp(connection, flags if flags is not None else runoptions.RunFlags(verbose = False))
    for name, value in items.items():
        setattr(app, name, value)
    if installed:
        connection.existing_paths.add(app.get_install_marker())
    return app


def test_only_remote_ubuntu_is_supported(isolated_settings):
    assert build_demo().get_supported_environments() == [constants.EnvironmentType.REMOTE_UBUNTU]


def test_images_use_pins_unless_overridden(isolated_settings, monkeypatch):
    monkeypatch.setitem(packages.docker_images, "demo", {"DEMO_IMAGE": "demo:1", "DEMO_DB_IMAGE": "db:1"})
    isolated_settings.set_value("UserData.Images", "demo_image", "  demo:2  ")
    isolated_settings.set_value("UserData.Images", "demo_db_image", "   ")
    app = build_demo()

    assert app.get_app_images() == {"DEMO_IMAGE": "demo:2", "DEMO_DB_IMAGE": "db:1"}
    assert app.get_image_env_lines() == "DEMO_IMAGE=demo:2\nDEMO_DB_IMAGE=db:1\n"


def test_an_app_without_pins_has_no_images(isolated_settings):
    assert build_demo().get_image_env_lines() == ""


def test_nginx_actions_follow_the_config_mode(isolated_settings):
    app = build_demo()
    assert app.get_nginx_action("install") == "install_conf"
    app.nginx_config_mode = "stream"
    assert app.get_nginx_action("install") == "install_stream_conf"


@pytest.mark.parametrize("value", [None, "", "  ", "None"])
def test_unset_required_settings_block_install(isolated_settings, value):
    app = build_demo()
    app.env_values["domain"] = value

    # domain is also set in nginx_config_values; that must not mask the blank.
    assert not app.check_required_settings()
    assert not app.install()
    assert app.connection.made_directories == []


def test_a_required_setting_in_no_source_is_missing(isolated_settings):
    app = build_demo()
    app.required_settings.append("admin_pass")
    assert not app.check_required_settings()


def test_present_required_settings_pass(isolated_settings):
    assert build_demo().check_required_settings()


@pytest.mark.parametrize("raw, expected", [("3", 3), (" 5 ", 5), ("0", 1), ("-2", 1), ("lots", 7)])
def test_backup_keep_is_a_positive_count(isolated_settings, raw, expected):
    isolated_settings.set_value("UserData.Backup", "backup_keep", raw)
    assert build_demo().get_backup_keep() == expected


def test_backup_identity_is_stripped(isolated_settings):
    isolated_settings.set_value("UserData.Backup", "backup_age_identity", " /keys/age.txt ")
    assert build_demo().get_backup_age_identity() == "/keys/age.txt"


def test_backup_dir_uses_the_label(isolated_settings):
    isolated_settings.set_value("UserData.Backup", "backup_root", "/mnt/b")
    app = build_demo()
    assert app.get_backup_dir() == "/mnt/b/demo"
    app.backup_label = "Demo"
    assert app.get_backup_dir() == "/mnt/b/Demo"


def test_backup_helper_image_can_be_overridden(isolated_settings):
    app = build_demo()
    assert app.get_helper_image() == packages.docker_images["_backup"]["BACKUP_HELPER_IMAGE"]
    isolated_settings.set_value("UserData.Images", "backup_helper_image", "busybox:1")
    assert app.get_helper_image() == "busybox:1"


###########################################################
# Backup and restore of directories and volumes
###########################################################

def test_backup_archives_directories_without_a_database(isolated_settings, tmp_path):
    app = build_demo(backup_dirs = ["data"], backup_excludes = ["cache"])
    script = app.build_backup_script("nightly")

    assert_valid_shell(script, tmp_path, "backup_dirs")
    assert "docker exec" not in script
    assert "--exclude=cache" in script
    assert "-v %s/data:/src:ro" % app.get_app_dir() in script
    assert "data.tar.gz\tdirectory" in script
    assert '_nightly"' in script


def test_retention_does_not_count_the_latest_symlink(isolated_settings):
    # latest/ matches the */ glob; counting it would keep one backup fewer.
    script = build_demo(backup_dirs = ["data"]).build_backup_script()
    assert '-e "/latest/$"' in script


def test_restore_extracts_directories_without_a_database(isolated_settings, tmp_path):
    app = build_demo(backup_dirs = ["data"], backup_volumes = ["db"])
    script = app.build_restore_script("20260101_000000")

    assert_valid_shell(script, tmp_path, "restore_dirs")
    assert 'archive_stream "data.tar.gz" | docker run --rm -i -v %s/data:/dst' % app.get_app_dir() in script
    assert "-v demo_db:/dst" in script
    assert "docker exec" not in script
    assert 'SRC="$BACKUP_BASE/20260101_000000"' in script


def test_backup_skips_an_app_that_is_not_installed(isolated_settings):
    app = build_demo(backup_dirs = ["data"])
    assert app.backup()
    assert not app.connection.called("run_blocking")


def test_backup_runs_the_script_server_side(isolated_settings):
    app = build_demo(installed = True, backup_dirs = ["data"])
    assert app.backup()
    assert app.connection.ran("bash", "Backup complete")


def test_a_failed_backup_reports_failure(isolated_settings):
    connection = RecordingConnection(
        command_output = {"docker ps -a": DEMO_RUNNING},
        return_codes = {"Backup complete": 2})
    assert not build_demo(connection, installed = True, backup_dirs = ["data"]).backup()


def test_restore_without_backup_items_does_nothing(isolated_settings):
    app = build_demo()
    assert app.restore()
    assert app.connection.commands == []


def test_restore_requires_an_installed_app(isolated_settings):
    app = build_demo(backup_dirs = ["data"])
    assert not app.restore()
    assert not app.connection.called("run_blocking")


def test_restore_aborts_when_the_snapshot_fails(isolated_settings):
    connection = RecordingConnection(
        command_output = {"docker ps -a": DEMO_RUNNING},
        return_codes = {"Backup complete": 1})
    app = build_demo(connection, installed = True, backup_dirs = ["data"])

    assert not app.restore()
    assert not connection.ran("Restore complete")


def test_restore_snapshots_then_restores_the_requested_backup(isolated_settings):
    flags = runoptions.RunFlags(verbose = False, backup_id = "20260101_000000")
    app = build_demo(installed = True, flags = flags, backup_dirs = ["data"])

    assert app.restore()
    strings = app.connection.command_strings()
    backup_index = next(i for i, s in enumerate(strings) if "_prerestore" in s)
    restore_index = next(i for i, s in enumerate(strings) if "Restore complete" in s)
    assert backup_index < restore_index
    assert "20260101_000000" in strings[restore_index]


def test_restore_defaults_to_latest(isolated_settings):
    app = build_demo(installed = True, backup_dirs = ["data"])
    assert app.restore()
    assert app.connection.ran("Restore complete", "/latest")


def test_a_failed_restore_reports_failure(isolated_settings):
    connection = RecordingConnection(
        command_output = {"docker ps -a": DEMO_RUNNING},
        return_codes = {"Restore complete": 3})
    assert not build_demo(connection, installed = True, backup_dirs = ["data"]).restore()


def test_restore_refuses_a_missing_identity_file(isolated_settings, tmp_path):
    isolated_settings.set_value("UserData.Backup", "backup_age_identity", str(tmp_path / "absent.txt"))
    app = build_demo(installed = True, backup_dirs = ["data"])

    assert not app.restore()
    assert not app.connection.ran("Restore complete")


def test_restore_stages_the_identity_on_tmpfs_and_removes_it(isolated_settings, tmp_path):
    identity = tmp_path / "age.txt"
    identity.write_text(DEMO_KEY)
    isolated_settings.set_value("UserData.Backup", "backup_age_identity", str(identity))
    app = build_demo(installed = True, backup_dirs = ["data"])

    assert app.restore()
    staged = "/dev/shm/joybox_age_demo.key"
    assert app.connection.written(staged) == DEMO_KEY
    assert (staged, "600") in app.connection.permissions
    assert staged in app.connection.removed_paths
    assert app.connection.ran("AGE_IDENTITY=%s" % staged)


def test_restore_removes_the_identity_even_when_the_restore_raises(isolated_settings, tmp_path):
    identity = tmp_path / "age.txt"
    identity.write_text(DEMO_KEY)
    isolated_settings.set_value("UserData.Backup", "backup_age_identity", str(identity))
    app = build_demo(installed = True, backup_dirs = ["data"])
    original = app.connection.run_blocking

    def run_blocking(cmd, sudo = False):
        if "Restore complete" in " ".join(cmd):
            raise RuntimeError("connection lost")
        return original(cmd, sudo = sudo)
    app.connection.run_blocking = run_blocking

    with pytest.raises(RuntimeError):
        app.restore()
    assert "/dev/shm/joybox_age_demo.key" in app.connection.removed_paths


def test_restore_fails_when_the_identity_cannot_be_staged(isolated_settings, tmp_path):
    identity = tmp_path / "age.txt"
    identity.write_text(DEMO_KEY)
    isolated_settings.set_value("UserData.Backup", "backup_age_identity", str(identity))
    connection = FailingWrites("/dev/shm/", command_output = {"docker ps -a": DEMO_RUNNING})
    app = build_demo(connection, installed = True, backup_dirs = ["data"])

    assert not app.restore()
    assert not connection.ran("Restore complete")


###########################################################
# Install and uninstall lifecycle
###########################################################

def test_install_stages_files_and_starts_compose(isolated_settings):
    app = build_demo()
    connection = app.connection
    app_dir = app.get_app_dir()

    assert app.install()
    assert connection.made_directories == [app_dir, f"{app_dir}/data", f"{app_dir}/config"]
    assert (app_dir, "700") in connection.permissions
    assert connection.written_files[f"{app_dir}/docker-compose.yml"] == "services: {}\n"
    assert connection.written_files[f"{app_dir}/.env"] == "DOMAIN=joybox.test\n"
    assert ("/tmp/demo.env", "600") in connection.permissions
    assert (f"{app_dir}/.env", "600") in connection.permissions
    assert "proxy_pass http://localhost:8080;" in connection.written("/tmp/demo.conf")
    assert connection.ran("manager_nginx.sh", "install_conf", "/tmp/demo.conf")
    assert connection.ran("manager_nginx.sh", "link_conf", "demo.conf")
    assert "/tmp/demo.conf" in connection.removed_paths
    assert connection.ran("manager_nginx.sh", "open_port", "9000")
    assert connection.ran("manager_nginx.sh", "systemctl", "restart")
    assert connection.ran("compose", "--env-file", f"{app_dir}/.env", "up", "-d", "--build")
    assert connection.written_files[app.get_install_marker()] == "demo\n"


def test_install_without_ports_opens_none(isolated_settings):
    app = build_demo(nginx_ports = [])
    assert app.install()
    assert not app.connection.ran("open_port")


@pytest.mark.parametrize("fragment", ["docker-compose.yml", "demo.env", "demo.conf"])
def test_install_stops_when_a_staged_file_cannot_be_written(isolated_settings, fragment):
    connection = FailingWrites(fragment)
    app = build_demo(connection)

    assert not app.install()
    assert not connection.ran("up", "-d")
    assert app.get_install_marker() not in connection.written_files


def test_the_default_post_install_succeeds(isolated_settings):
    assert build_demo().post_install()


def test_service_health_waits_on_the_compose_service(isolated_settings):
    app = build_demo()
    assert app.wait_for_service_health("web", timeout_seconds = 12)
    assert app.connection.ran("seq 1 12", "com.docker.compose.service=web", "com.docker.compose.project=demo")


def test_service_health_reports_a_timeout(isolated_settings):
    connection = RecordingConnection(return_codes = {"Timed out waiting for web": 1})
    assert not build_demo(connection).wait_for_service_health("web")


def test_uninstall_keeps_data_and_closes_ports(isolated_settings):
    app = build_demo()
    connection = app.connection
    app_dir = app.get_app_dir()

    assert app.uninstall()
    assert connection.ran("compose", "down")
    assert not connection.ran("down", "-v")
    assert connection.moved[0][0] == app_dir
    assert connection.ran("manager_nginx.sh", "remove_conf", "demo.conf")
    assert connection.ran("manager_nginx.sh", "close_port", "9000")
    assert connection.ran("manager_nginx.sh", "systemctl", "restart")


def test_uninstall_without_ports_closes_none(isolated_settings):
    app = build_demo(nginx_ports = [])
    assert app.uninstall()
    assert not app.connection.ran("close_port")
