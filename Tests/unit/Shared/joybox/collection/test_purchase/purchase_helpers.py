# Local imports
from joybox import config


class FakePurchase:

    def __init__(self, **values):
        self.values = dict(values)

    def get_value(self, key):
        return self.values.get(key)

    def set_value(self, key, value):
        self.values[key] = value

    def get_data_copy(self):
        return dict(self.values)


class FakeStore:

    def __init__(
        self,
        purchases = None,
        can_import = True,
        can_download = True,
        identifier_key = config.json_key_store_appid,
        latest_url = None,
        latest_version = "1.0",
        saved_login = True,
        listable = True):
        self.purchases = purchases if purchases is not None else []
        self.saved_login = saved_login
        self.listable = listable
        self.fetches = 0
        self.can_import = can_import
        self.can_download = can_download
        self.identifier_key = identifier_key
        self.latest_url = latest_url
        self.latest_version = latest_version
        self.downloads = []
        self.logged_in = False

    def get_type(self):
        return "FakeStore"

    def get_key(self):
        return "fakestore"

    def get_supercategory(self):
        return config.Supercategory.ROMS

    def get_category(self):
        return config.Category.COMPUTER

    def get_subcategory(self):
        return config.subcategory_map[config.Category.COMPUTER][0]

    def get_info_identifier_key(self):
        return self.identifier_key

    def can_import_purchases(self):
        return self.can_import

    def can_download_purchases(self):
        return self.can_download

    def has_saved_login(self):
        return self.saved_login

    def get_login_hint(self):
        return "sign in to FakeStore"

    def get_latest_purchases(self, **kwargs):
        self.fetches += 1
        return self.purchases if self.listable else None

    def get_latest_url(self, identifier, **kwargs):
        return self.latest_url

    def get_latest_version(self, identifier, **kwargs):
        return self.latest_version

    def download(self, **kwargs):
        self.downloads.append(kwargs)
        return True


def a_purchase(appid = "220", name = "Half-Life 2", appurl = None, appname = None):
    return FakePurchase(**{
        config.json_key_store_appid: appid,
        config.json_key_store_appname: appname,
        config.json_key_store_appurl: appurl,
        config.json_key_store_name: name,
    })
