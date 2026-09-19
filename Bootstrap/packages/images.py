# Imports
import os
import sys

###########################################################
# Docker images
#
# Central pin list for every container image JoyBox deploys. This is the one
# place to look at, or bump, a version.
#
# Pins are minor-line tags rather than exact patch releases: the major/minor
# stays deterministic so a rebuild months later cannot silently jump a major
# version, while patch-level security fixes still flow on a rebuild. Never
# use "latest" here.
#
# Each app maps an env var name to a pin. The Docker app installer appends
# those env vars to the app's .env file, and the compose template refers to
# them as ${VAR}. Any pin can be overridden per-server by setting the same
# name, lowercased, under [UserData.Images] in JoyBox.ini.
#
# To roll an app forward:
#   1. bump the tag here
#   2. python3 bootstrap.py -t remote_ubuntu --list-images     (confirm)
#   3. python3 bootstrap.py -a setup -t remote_ubuntu -s 0 --components <app> -f
###########################################################
docker_images = {}

# Backup helper
# Used by backup/restore to read container volumes and bind mounts. Under
# "userns-remap" those files are owned by an offset uid the SSH user cannot
# read, so archiving has to happen inside a container.
docker_images["_backup"] = {
    "BACKUP_HELPER_IMAGE": "alpine:3.22"
}

# Audiobookshelf
docker_images["audiobookshelf"] = {
    "AUDIOBOOKSHELF_IMAGE": "advplyr/audiobookshelf:2.36.0"
}

# FileBrowser
docker_images["filebrowser"] = {
    "FILEBROWSER_IMAGE": "filebrowser/filebrowser:v2.63.23"
}

# Jenkins
docker_images["jenkins"] = {
    "JENKINS_IMAGE": "jenkins/jenkins:lts-jdk21"
}

# Kanboard
docker_images["kanboard"] = {
    "KANBOARD_IMAGE": "kanboard/kanboard:v1.2.54"
}

# Open OSCAR Server
# Built from source: upstream publishes no container image. OSCAR_VERSION is the
# git tag to build, so it is the pin that actually matters here.
docker_images["oscar"] = {
    "OSCAR_VERSION": "v0.24.0",
    "OSCAR_BUILDER_IMAGE": "golang:1.26.2-alpine",
    "OSCAR_RUNTIME_IMAGE": "alpine:3.22"
}

# Navidrome
docker_images["navidrome"] = {
    "NAVIDROME_IMAGE": "deluan/navidrome:0.64.0"
}

# Wordpress
# The db pin replaces mysql:5.7, which has been end-of-life since October 2023.
# The cli image is the official wp-cli sidecar used to seed site content.
docker_images["wordpress"] = {
    "WORDPRESS_IMAGE": "wordpress:7.1-php8.5-apache",
    "WORDPRESS_CLI_IMAGE": "wordpress:cli-php8.5",
    "WORDPRESS_DB_IMAGE": "mariadb:11.8"
}
