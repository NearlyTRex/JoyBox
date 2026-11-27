# Nintendo Switch user profiles: what a profile id and account name must look like.
# Kept apart from switch.py so lookups of emulator config can check a profile without
# importing the file tools.

# Check if switch profile info is valid
def is_valid_switch_profile_info(user_id, account_name):

    # Check user id
    if not isinstance(user_id, str) or len(user_id) != 32:
        return False

    # The id is converted with fromhex, which raises on anything else
    try:
        bytearray.fromhex(user_id)
    except ValueError:
        return False

    # Check account name
    if not isinstance(account_name, str) or len(account_name) > 32:
        return False
    if len(account_name) == 0:
        return False

    # Should be good
    return True
