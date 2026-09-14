#!/bin/sh
#
# JoyBox WordPress seed script.
#
# Runs inside the official wordpress:cli container against the live site.
# Invoked by installers/installer_wordpress.py after the site is healthy.
#
# This script is idempotent and is expected to run on every setup. Pages are
# tracked by the post meta key _joybox_seed_id rather than by slug or title,
# so renaming a page in wp-admin does not cause a duplicate to be recreated.
# Existing content is left alone unless SEED_OVERWRITE=1 is set: your edits
# win over the repo by default.
#
# Content lives in content/ as HTML fragments. To add a page, drop a file in
# there and add a seed_page line at the bottom of this script.

set -eu

SEED_DIR="$(dirname "$0")"
CONTENT_DIR="$SEED_DIR/content"
SEED_VERSION=1

log() { echo "[seed] $*"; }

# Install core if this is a fresh database
if ! wp core is-installed 2>/dev/null; then
    log "Installing WordPress core at $WP_SITE_URL"
    wp core install \
        --url="$WP_SITE_URL" \
        --title="$WP_SITE_TITLE" \
        --admin_user="$WP_ADMIN_USER" \
        --admin_password="$WP_ADMIN_PASS" \
        --admin_email="$WP_ADMIN_EMAIL" \
        --skip-email
else
    log "WordPress core already installed"
fi

# Canonical URLs. The apex is canonical; nginx 301s www to it.
wp option update home "$WP_SITE_URL"
wp option update siteurl "$WP_SITE_URL"
wp option update blogname "$WP_SITE_TITLE"
[ -n "${WP_SITE_TAGLINE:-}" ] && wp option update blogdescription "$WP_SITE_TAGLINE"

# Pretty permalinks
wp option update permalink_structure '/%postname%/'
wp rewrite flush --hard || true

# Drop the default sample content that ships with a fresh install
if wp post list --post_type=post --name=hello-world --format=ids | grep -q .; then
    log "Removing default 'Hello world!' post"
    wp post delete $(wp post list --post_type=post --name=hello-world --format=ids) --force
fi
if wp post list --post_type=page --name=sample-page --format=ids | grep -q .; then
    log "Removing default 'Sample Page'"
    wp post delete $(wp post list --post_type=page --name=sample-page --format=ids) --force
fi

# Create or update a page, tracked by seed id
# Usage: seed_page <seed-id> <title> <content-file>
seed_page() {
    seed_id="$1"
    title="$2"
    content_file="$CONTENT_DIR/$3"

    if [ ! -f "$content_file" ]; then
        log "WARNING: missing content file $content_file, skipping $seed_id"
        return 0
    fi

    existing="$(wp post list --post_type=page --meta_key=_joybox_seed_id \
        --meta_value="$seed_id" --format=ids --posts_per_page=1)"

    if [ -z "$existing" ]; then
        log "Creating page '$title'"
        new_id="$(wp post create \
            --post_type=page \
            --post_status=publish \
            --post_title="$title" \
            --post_content="$(cat "$content_file")" \
            --porcelain)"
        wp post meta add "$new_id" _joybox_seed_id "$seed_id"
    elif [ "${SEED_OVERWRITE:-0}" = "1" ]; then
        log "Overwriting page '$title' (SEED_OVERWRITE=1)"
        wp post update "$existing" --post_content="$(cat "$content_file")"
    else
        log "Page '$title' already exists, leaving it alone"
    fi
}

# Ensure a menu exists and contains the seeded pages
seed_menu() {
    menu_name="$1"
    if ! wp menu list --fields=slug --format=csv | tail -n +2 | grep -qx "$(echo "$menu_name" | tr 'A-Z ' 'a-z-')"; then
        log "Creating menu '$menu_name'"
        wp menu create "$menu_name"
    fi
}

###########################################################
# Site content
#
# Add pages here. This is the part to edit in a later session.
###########################################################

seed_page "home"  "Home"  "home.html"
seed_page "about" "About" "about.html"

seed_menu "Main"

# Use the Home page as the front page
home_id="$(wp post list --post_type=page --meta_key=_joybox_seed_id --meta_value=home --format=ids --posts_per_page=1)"
if [ -n "$home_id" ]; then
    wp option update show_on_front page
    wp option update page_on_front "$home_id"
fi

wp option update joybox_seed_version "$SEED_VERSION"
log "Seed complete (version $SEED_VERSION)"
