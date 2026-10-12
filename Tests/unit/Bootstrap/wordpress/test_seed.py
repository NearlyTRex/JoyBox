# Imports
import os

# Third-party imports
import pytest


###########################################################
# WordPress seed
#
# The seed runs on every setup against the live site, so a second run must
# leave the site as the first one did and must never overwrite edits made in
# wp-admin unless asked to. It runs here against a stand-in wp that keeps the
# site in files.
###########################################################

SCRIPT = "Bootstrap/wordpress/seed.sh"
SITE = "/var/lib/wp"
SEED_HOME = "/root/seed"

# A WordPress kept in files: posts by type and slug, seeded pages by seed id,
# options and menus
FAKE_WP = r"""SITE=/var/lib/wp
mkdir -p "$SITE/posts" "$SITE/seed" "$SITE/options"
arg() { for a in "$@"; do case "$a" in --$KEY=*) echo "${a#--$KEY=}"; return ;; esac; done; }
case "$1 $2" in
    "core is-installed") [ -e "$SITE/installed" ] ;;
    "core install") touch "$SITE/installed" ;;
    "option update") printf '%s' "$4" > "$SITE/options/$3" ;;
    "rewrite flush") exit "${WP_FLUSH_EXIT:-0}" ;;
    "post list")
        KEY=meta_value; seed=$(arg "$@")
        KEY=post_type; type=$(arg "$@")
        KEY=name; name=$(arg "$@")
        if [ -n "$seed" ]; then
            cat "$SITE/seed/$seed" 2>/dev/null || true
        else
            cat "$SITE/posts/$type-$name" 2>/dev/null || true
        fi ;;
    "post delete") echo "$3" >> "$SITE/deleted" ;;
    "post create")
        id=$(( $(cat "$SITE/next_id" 2>/dev/null || echo 10) + 1 ))
        echo "$id" > "$SITE/next_id"
        KEY=post_content; arg "$@" > "$SITE/content-$id"
        echo "$id" ;;
    "post meta") printf '%s' "$4" > "$SITE/seed/$6" ;;
    "post update") KEY=post_content; arg "$@" > "$SITE/content-$3" ;;
    "menu list") echo slug; cat "$SITE/menus" 2>/dev/null || true ;;
    "menu create") echo "$3" | tr 'A-Z ' 'a-z-' >> "$SITE/menus" ;;
esac
"""

ENV = {
    "WP_SITE_URL": "https://joybox.test",
    "WP_SITE_TITLE": "JoyBox",
    "WP_ADMIN_USER": "admin",
    "WP_ADMIN_PASS": "secret",
    "WP_ADMIN_EMAIL": "admin@joybox.test",
}


@pytest.fixture
def site(shell_sandbox):
    shell_sandbox.stub("wp", script = FAKE_WP)
    shell_sandbox.write(SEED_HOME + "/content/home.html", "<p>home</p>")
    shell_sandbox.write(SEED_HOME + "/content/about.html", "<p>about</p>")
    return shell_sandbox


# Run the repository's seed with its content directory beside a chosen $0
def seed(site, **env):
    script = os.path.join(site.repo_root, SCRIPT)
    return site.run_command(["bash", "-c", '. "$1"', SEED_HOME + "/seed.sh", script], env = dict(ENV, **env))


def wp_ran(site, *args):
    return site.ran("wp", *args)


def option(site, name):
    return site.read("%s/options/%s" % (SITE, name))


###########################################################
# Core
###########################################################

def test_a_fresh_database_gets_core_installed(site):
    result = seed(site)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "--url=https://joybox.test" in [arg for call in site.calls("wp") if call[:2] == ["core", "install"] for arg in call]


def test_an_installed_site_is_not_reinstalled(site):
    site.write(SITE + "/installed", "")

    result = seed(site)

    assert result.returncode == 0
    assert "core already installed" in result.stdout
    assert not wp_ran(site, "core", "install")


def test_the_apex_is_the_canonical_url(site):
    seed(site)

    assert option(site, "home") == "https://joybox.test"
    assert option(site, "siteurl") == "https://joybox.test"
    assert option(site, "blogname") == "JoyBox"
    assert option(site, "permalink_structure") == "/%postname%/"


def test_a_tagline_is_set_only_when_given(site):
    seed(site)
    assert not site.exists(SITE + "/options/blogdescription")

    seed(site, WP_SITE_TAGLINE = "Games")
    assert option(site, "blogdescription") == "Games"


def test_a_failed_rewrite_flush_does_not_stop_the_seed(site):
    result = seed(site, WP_FLUSH_EXIT = "1")

    assert result.returncode == 0


###########################################################
# Sample content
###########################################################

def test_the_default_sample_content_is_removed(site):
    site.write(SITE + "/posts/post-hello-world", "1 5\n")
    site.write(SITE + "/posts/page-sample-page", "2\n")

    seed(site)

    assert site.read(SITE + "/deleted").split() == ["1", "5", "2"]


def test_nothing_is_deleted_without_sample_content(site):
    seed(site)

    assert not wp_ran(site, "post", "delete")


###########################################################
# Pages
###########################################################

def test_pages_are_created_and_tagged_with_their_seed_id(site):
    seed(site)

    assert site.read(SITE + "/seed/home") == "11"
    assert site.read(SITE + "/seed/about") == "12"
    assert site.read(SITE + "/content-11").strip() == "<p>home</p>"


def test_the_home_page_becomes_the_front_page(site):
    seed(site)

    assert option(site, "show_on_front") == "page"
    assert option(site, "page_on_front") == "11"


def test_existing_pages_are_left_alone(site):
    seed(site)
    site.write(SEED_HOME + "/content/home.html", "<p>changed</p>")

    result = seed(site)

    assert "already exists, leaving it alone" in result.stdout
    assert site.read(SITE + "/content-11").strip() == "<p>home</p>"
    assert not wp_ran(site, "post", "update")


def test_overwrite_replaces_existing_content(site):
    seed(site)
    site.write(SEED_HOME + "/content/home.html", "<p>changed</p>")

    seed(site, SEED_OVERWRITE = "1")

    assert site.read(SITE + "/content-11").strip() == "<p>changed</p>"


def test_a_missing_content_file_skips_its_page(site):
    os.remove(site.host_path(SEED_HOME + "/content/home.html"))

    result = seed(site)

    assert result.returncode == 0
    assert "missing content file" in result.stdout
    assert not site.exists(SITE + "/seed/home")
    assert site.exists(SITE + "/seed/about")


def test_without_a_home_page_the_front_page_is_untouched(site):
    os.remove(site.host_path(SEED_HOME + "/content/home.html"))

    seed(site)

    assert not site.exists(SITE + "/options/page_on_front")


###########################################################
# Menu and version
###########################################################

def test_the_main_menu_is_created_once(site):
    seed(site)
    seed(site)

    assert site.read(SITE + "/menus") == "main\n"


def test_the_seed_version_is_recorded(site):
    result = seed(site)

    assert option(site, "joybox_seed_version") == "1"
    assert "Seed complete (version 1)" in result.stdout
