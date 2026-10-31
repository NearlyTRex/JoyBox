# Imports
import json
import re

# Local imports
import joybox.config as config
import joybox.sync as sync
import joybox.logger as logger
import joybox.paths as paths
import joybox.secretstore as secretstore
import joybox.serialization as serialization
import joybox.settings as settings

###########################################################
# Signing a remote locker in with OAuth
#
# The remote's options, client and token included, are kept in the 1Password
# field the locker's _config setting references. They are only stored once
# the new token is known to list the locker folder.
###########################################################

# Remote types that sign in with an OAuth token
OAUTH_REMOTE_TYPES = [config.RemoteType.DRIVE]

# Options that sign in some other way, dropped once there is a token
REPLACED_OPTIONS = ["service_account_credentials", "service_account_file"]

# What a Drive folder id looks like, and where it sits in a folder's URL
FOLDER_ID = re.compile(r"^[A-Za-z0-9_-]+$")
FOLDER_URL = re.compile(r"/folders/([A-Za-z0-9_-]+)")

# The settings section lockers are kept in
SHARE_SECTION = "UserData.Share"

# Get a locker's setting key prefix
def get_locker_key(locker_type):
    return "locker_%s" % locker_type.lower()

# Get a locker's remote as (type, name, path), or None when it cannot sign in
# with OAuth
def get_locker_remote(locker_type):
    locker_key = get_locker_key(locker_type)
    remote_type = settings.get_value(SHARE_SECTION, locker_key + "_type", throw_exception = False)
    remote_name = settings.get_value(SHARE_SECTION, locker_key + "_name", throw_exception = False)
    remote_path = settings.get_value(SHARE_SECTION, locker_key + "_remote_path", throw_exception = False) or "/"
    if not remote_type or not remote_name:
        logger.log_error("Locker '%s' is not a remote locker" % locker_type)
        return None
    if config.RemoteType.from_string(remote_type) not in OAUTH_REMOTE_TYPES:
        logger.log_error("Locker '%s' is a %s remote, which does not sign in with OAuth" % (locker_type, remote_type))
        return None
    return (remote_type, remote_name, remote_path)

# Get the 1Password reference a locker's options are stored at, or None
def get_options_reference(locker_type):
    setting = get_locker_key(locker_type) + "_config"
    reference = settings.get_raw_value(SHARE_SECTION, setting, throw_exception = False)
    if not secretstore.parse_secret_reference(reference or ""):
        logger.log_error("Set %s in [%s] to the 1Password field to store the options in, such as %s" % (
            setting, SHARE_SECTION, "op://Personal/JoyBox/%s/%s" % (SHARE_SECTION, setting)))
        return None
    return reference

# Get the options stored now, or none
def read_stored_options(reference):
    stored = secretstore.resolve_value(reference)
    if not stored:
        return {}
    options = serialization.parse_json_string(stored)
    return options if isinstance(options, dict) else {}

# Get the client id and secret from a downloaded client file
def read_client_file(path):
    if not paths.does_path_exist(path):
        logger.log_error("Client file %s does not exist" % path)
        return None
    data = serialization.read_json_file(path)
    if not isinstance(data, dict):
        data = {}
    if "web" in data:
        logger.log_error("Client file %s is for a web application; create a Desktop app client" % path)
        return None
    client = data.get("installed") or {}
    if not client.get("client_id") or not client.get("client_secret"):
        logger.log_error("Client file %s has no client id and secret" % path)
        return None
    return (client["client_id"], client["client_secret"])

# Get the client from its file, or the stored one when there is no file
def choose_client(client_file, options):
    if client_file:
        return read_client_file(client_file)
    if options.get("client_id") and options.get("client_secret"):
        return (options["client_id"], options["client_secret"])
    logger.log_error("No client is stored; pass --client_file")
    return None

# Get a folder id from an id or a folder's URL
def parse_folder_id(value):
    value = (value or "").strip()
    match = FOLDER_URL.search(value)
    if match:
        return match.group(1)
    if FOLDER_ID.match(value):
        return value
    return None

# Get the folder given, or the stored one when none is
def choose_folder(folder_id, options):
    if folder_id:
        parsed = parse_folder_id(folder_id)
        if not parsed:
            logger.log_error("%s is not a folder id or folder URL" % folder_id)
        return parsed
    if options.get("root_folder_id"):
        return options["root_folder_id"]
    logger.log_error("No folder is stored; pass --folder_id")
    return None

# Build the options to store, keeping what else was stored
def build_options(options, client, folder_id, token):
    built = {key: value for key, value in options.items() if key not in REPLACED_OPTIONS}
    built.update({
        "client_id": client[0],
        "client_secret": client[1],
        "token": token,
        "root_folder_id": folder_id,
    })
    return built

# Sign a locker in, check the new options list its folder, and store them
def sign_in_locker(
    locker_type,
    remote,
    reference,
    options,
    client,
    folder_id,
    open_browser = True,
    verbose = False):
    remote_type, remote_name, remote_path = remote
    token = sync.authorize_remote(
        remote_type = remote_type,
        client_id = client[0],
        client_secret = client[1],
        open_browser = open_browser,
        verbose = verbose)
    if not token:
        return False

    # Every rclone command reads the locker's options from the settings, so
    # setting them in memory has the check use the new ones
    new_options = build_options(options, client, folder_id, token)
    settings.set_value(SHARE_SECTION, get_locker_key(locker_type) + "_config", json.dumps(new_options))
    entries = sync.count_remote_entries(remote_name = remote_name, remote_type = remote_type, remote_path = remote_path, verbose = verbose)
    if entries is None:
        logger.log_error("The new token cannot list %s:%s; nothing was stored" % (remote_name, remote_path))
        return False
    logger.log_info("Signed in; %s:%s has %d entries at its top level" % (remote_name, remote_path, entries))
    if not secretstore.store_secret_reference(reference, json.dumps(new_options), verbose = verbose):
        return False
    logger.log_info("Stored the options in %s" % reference)
    return True
