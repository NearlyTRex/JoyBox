# Local imports
from joybox import config
from joybox import jsondata

# Search result
class SearchResult(jsondata.JsonData):


    # Store the provider's identifier for the result
    def set_id(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_ID, value)
    # The provider's identifier for the result; None when unset
    def get_id(self):
        return self.get_value(config.SEARCH_RESULT_KEY_ID)

    # Store the result's display title
    def set_title(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_TITLE, value)
    # The result's display title; None when unset
    def get_title(self):
        return self.get_value(config.SEARCH_RESULT_KEY_TITLE)

    # Store the result's summary text
    def set_description(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_DESCRIPTION, value)
    # The result's summary text, falling back to its title when unset
    def get_description(self):
        return self.get_value(config.SEARCH_RESULT_KEY_DESCRIPTION, self.get_title())

    # Store the link the result points at
    def set_url(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_URL, value)
    # The link the result points at; None when unset
    def get_url(self):
        return self.get_value(config.SEARCH_RESULT_KEY_URL)

    # Store when the result was published
    def set_date(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_DATE, value)
    # When the result was published; None when unset
    def get_date(self):
        return self.get_value(config.SEARCH_RESULT_KEY_DATE)

    # Store the score used to rank the result against others
    def set_relevance(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_RELEVANCE, value)
    # The score used to rank the result against others; None when unset
    def get_relevance(self):
        return self.get_value(config.SEARCH_RESULT_KEY_RELEVANCE)

    # Store data the result carries; set_data and get_data are the whole document's
    def set_result_data(self, value):
        self.set_value(config.SEARCH_RESULT_KEY_DATA, value)
    # Data the result carries, not the whole document; None when unset
    def get_result_data(self):
        return self.get_value(config.SEARCH_RESULT_KEY_DATA)

# Asset search result
class AssetSearchResult(SearchResult):


    # Store the asset's media type, such as image/png
    def set_mime(self, value):
        self.set_value(config.ASSET_KEY_MIME, value)
    # The asset's media type, such as image/png; None when unset
    def get_mime(self):
        return self.get_value(config.ASSET_KEY_MIME)

    # Store the asset's horizontal size in pixels
    def set_width(self, value):
        self.set_value(config.ASSET_KEY_WIDTH, value)
    # The asset's horizontal size in pixels; None when unset
    def get_width(self):
        return self.get_value(config.ASSET_KEY_WIDTH)

    # Store the asset's vertical size in pixels
    def set_height(self, value):
        self.set_value(config.ASSET_KEY_HEIGHT, value)
    # The asset's vertical size in pixels; None when unset
    def get_height(self):
        return self.get_value(config.ASSET_KEY_HEIGHT)

    # Store the asset's play length, for video or audio
    def set_duration(self, value):
        self.set_value(config.ASSET_KEY_DURATION, value)
    # The asset's play length, for video or audio; None when unset
    def get_duration(self):
        return self.get_value(config.ASSET_KEY_DURATION)
