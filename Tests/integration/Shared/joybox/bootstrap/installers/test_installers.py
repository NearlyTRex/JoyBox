# Imports
import importlib
import os
import re
import shutil
import subprocess

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.installers as installers
###########################################################
# Generated artifacts, validated by the real tools
#
# Unit tests assert on the content of these; here the output is handed to docker
# and bash, which catches what reads fine and parses badly.
###########################################################

DOCKER_APPS = [
    "Audiobookshelf",
    "FileBrowser",
    "FitLog",
    "Jenkins",
    "Kanboard",
    "Navidrome",
    "Oscar",
    "Wordpress",
]

REQUIRED_SETTINGS = [
    ("UserData.Wordpress", "wordpress_db_pass", "dbpass"),
    ("UserData.Wordpress", "wordpress_db_root_pass", "rootpass"),
    ("UserData.Wordpress", "wordpress_admin_pass", "adminpass"),
    ("UserData.Wordpress", "wordpress_admin_email", "nobody@joybox.test"),
    ("UserData.FileBrowser", "filebrowser_user_root", "/mnt/storage"),
    ("UserData.FileBrowser", "filebrowser_admin_pass", "adminpass"),
    ("UserData.Jenkins", "jenkins_home_dir", "/mnt/repositories"),
    ("UserData.Backup", "backup_root", "/mnt/storage/Backups"),
]

docker_available = shutil.which("docker") is not None


@pytest.fixture
def populated_settings(isolated_settings):
    for section, key, value in REQUIRED_SETTINGS:
        isolated_settings.set_value(section, key, value)
    return isolated_settings


def build_installer(app_name, connection):
    return getattr(installers, app_name)(connection)


def render_env(installer):
    # Image pins are appended separately from packages/images.py, so rendering
    # only the template leaves every ${..._IMAGE} reference unset.
    return installer.env_template.format(**installer.env_values) + installer.get_image_env_lines()


def nginx_template_for(app_name, installer):
    # Cockpit and Certbot format the module-level template directly rather than
    # assigning it to the instance, so fall back to the module.
    template = getattr(installer, "nginx_config_template", "")
    if template:
        return template
    module = importlib.import_module(f"joybox.bootstrap.installers.installer_{app_name.lower()}")
    return getattr(module, "nginx_config_template", "")


###########################################################
# Compose files
###########################################################

@pytest.mark.parametrize("app_name", DOCKER_APPS)
@pytest.mark.skipif(not docker_available, reason = "docker is not installed")
@pytest.mark.requires_docker
@pytest.mark.slow
def test_compose_template_is_valid(app_name, populated_settings, recording_connection, tmp_path):
    installer = build_installer(app_name, recording_connection)

    app_dir = tmp_path / app_name
    app_dir.mkdir()
    (app_dir / "docker-compose.yml").write_text(installer.docker_compose_template)
    (app_dir / ".env").write_text(render_env(installer))

    result = subprocess.run(
        ["docker", "compose", "config", "--quiet"],
        cwd = str(app_dir),
        capture_output = True,
        text = True,
        timeout = 120)

    assert result.returncode == 0, (
        f"{app_name} compose file is invalid:\n{result.stderr[-2000:]}")


@pytest.mark.parametrize("app_name", DOCKER_APPS)
@pytest.mark.skipif(not docker_available, reason = "docker is not installed")
@pytest.mark.requires_docker
@pytest.mark.slow
def test_compose_publishes_only_on_loopback(app_name, populated_settings, recording_connection, tmp_path):
    # Docker's resolved view, so an env var expanding to a bare port cannot pass.
    installer = build_installer(app_name, recording_connection)

    app_dir = tmp_path / app_name
    app_dir.mkdir()
    (app_dir / "docker-compose.yml").write_text(installer.docker_compose_template)
    (app_dir / ".env").write_text(render_env(installer))

    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd = str(app_dir),
        capture_output = True,
        text = True,
        timeout = 120)
    assert result.returncode == 0, result.stderr[-2000:]

    for line in result.stdout.split("\n"):
        stripped = line.strip()
        if stripped.startswith("published:"):
            continue
        if "host_ip:" in stripped:
            assert "127.0.0.1" in stripped, \
                f"{app_name} publishes on {stripped}, which ufw does not govern"


###########################################################
# Generated shell
###########################################################

@pytest.mark.parametrize("app_name", DOCKER_APPS)
def test_backup_script_parses(app_name, populated_settings, recording_connection, tmp_path):
    installer = build_installer(app_name, recording_connection)
    if not installer.has_backup_items():
        pytest.skip(f"{app_name} declares no backup data")

    script_path = tmp_path / f"{app_name}-backup.sh"
    script_path.write_text(installer.build_backup_script())

    result = subprocess.run(["bash", "-n", str(script_path)], capture_output = True, text = True)
    assert result.returncode == 0, f"{app_name} backup script:\n{result.stderr}"


@pytest.mark.parametrize("app_name", DOCKER_APPS)
def test_restore_script_parses(app_name, populated_settings, recording_connection, tmp_path):
    installer = build_installer(app_name, recording_connection)
    if not installer.has_backup_items():
        pytest.skip(f"{app_name} declares no backup data")

    script_path = tmp_path / f"{app_name}-restore.sh"
    script_path.write_text(installer.build_restore_script("latest", "/dev/shm/key"))

    result = subprocess.run(["bash", "-n", str(script_path)], capture_output = True, text = True)
    assert result.returncode == 0, f"{app_name} restore script:\n{result.stderr}"


@pytest.mark.parametrize("app_name", DOCKER_APPS)
def test_encrypted_backup_script_parses(app_name, populated_settings, recording_connection, tmp_path):
    # The age step sits inside a docker exec pipe, the most quoting-sensitive line.
    populated_settings.set_value("UserData.Backup", "backup_age_recipient", "age1example")
    installer = build_installer(app_name, recording_connection)
    if not installer.has_backup_items():
        pytest.skip(f"{app_name} declares no backup data")

    script_path = tmp_path / f"{app_name}-backup-encrypted.sh"
    script_path.write_text(installer.build_backup_script())

    result = subprocess.run(["bash", "-n", str(script_path)], capture_output = True, text = True)
    assert result.returncode == 0, f"{app_name} encrypted backup script:\n{result.stderr}"


###########################################################
# Nginx vhosts
###########################################################

@pytest.mark.parametrize("app_name", DOCKER_APPS + ["Cockpit", "Certbot"])
def test_nginx_template_renders_and_is_balanced(app_name, populated_settings, recording_connection):
    # An unbalanced brace produces a config that takes every site down.
    installer = build_installer(app_name, recording_connection)
    template = nginx_template_for(app_name, installer)
    if not template:
        pytest.skip(f"{app_name} has no nginx template")

    rendered = template.format(**installer.nginx_config_values)

    assert rendered.count("{") == rendered.count("}"), \
        f"{app_name} vhost has unbalanced braces"
    assert "server_name" in rendered

    # nginx would reject a literal "{domain}" at load time.
    leftovers = re.findall(r"\{[a-z_]+\}", rendered)
    assert not leftovers, f"{app_name} vhost has unrendered placeholders: {set(leftovers)}"
