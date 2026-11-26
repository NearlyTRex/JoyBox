# Local imports
from joybox import config
from joybox import jsondata

# Search result
class SearchResult(jsondata.JsonData):

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        super().__init__(json_data, json_platform)

    # Id
    def set_id(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_ID, value)
    def get_id(self):
        return self.get_value(config.SEARCH_RESULT_KEY_ID)

    # Title
    def set_title(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_TITLE, value)
    def get_title(self):
        return self.get_value(config.SEARCH_RESULT_KEY_TITLE)

    # Description
    def set_description(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_DESCRIPTION, value)
    def get_description(self):
        return self.get_value(config.SEARCH_RESULT_KEY_DESCRIPTION, self.get_title())

    # Url
    def set_url(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_URL, value)
    def get_url(self):
        return self.get_value(config.SEARCH_RESULT_KEY_URL)

    # Date
    def set_date(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_DATE, value)
    def get_date(self):
        return self.get_value(config.SEARCH_RESULT_KEY_DATE)

    # Relevance
    def set_relevance(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_RELEVANCE, value)
    def get_relevance(self):
        return self.get_value(config.SEARCH_RESULT_KEY_RELEVANCE)

    # Data the result carries; set_data and get_data are the whole document's
    def set_result_data(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_DATA, value)
    def get_result_data(self):
        return self.get_value(config.SEARCH_RESULT_KEY_DATA)

# Asset search result
class AssetSearchResult(SearchResult):

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        super().__init__(json_data, json_platform)

    # Mime
    def set_mime(self, value):
        self.set_value(config.ASSET_KEY_MIME, value)
    def get_mime(self):
        return self.get_value(config.ASSET_KEY_MIME)

    # Width
    def set_width(self, value):
        self.set_value(config.ASSET_KEY_WIDTH, value)
    def get_width(self):
        return self.get_value(config.ASSET_KEY_WIDTH)

    # Height
    def set_height(self, value):
        self.set_value(config.ASSET_KEY_HEIGHT, value)
    def get_height(self):
        return self.get_value(config.ASSET_KEY_HEIGHT)

    # Duration
    def set_duration(self, value):
        self.set_value(config.ASSET_KEY_DURATION, value)
    def get_duration(self):
        return self.get_value(config.ASSET_KEY_DURATION)
