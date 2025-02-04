# Imports
import os, os.path
import sys

# Local imports
import config
import jsondata

# Search result
class SearchResult(jsondata.JsonData):

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        super().__init__(json_data, json_platform)

    # Id
    def set_id(self, value):
        self.set_value(config.search_result_key_id, value)
    def get_id(self):
        return self.get_value(config.search_result_key_id)

    # Title
    def set_title(self, value):
        self.set_value(config.search_result_key_title, value)
    def get_title(self):
        return self.get_value(config.search_result_key_title)

    # Description
    def set_description(self, value):
        self.set_value(config.search_result_key_description, value)
    def get_description(self):
        return self.get_value(config.search_result_key_description, self.get_title())

    # Url
    def set_url(self, value):
        self.set_value(config.search_result_key_url, value)
    def get_url(self):
        return self.get_value(config.search_result_key_url)

    # Date
    def set_date(self, value):
        self.set_value(config.search_result_key_date, value)
    def get_date(self):
        return self.get_value(config.search_result_key_date)

    # Relevance
    def set_relevance(self, value):
        self.set_value(config.search_result_key_relevance, value)
    def get_relevance(self):
        return self.get_value(config.search_result_key_relevance)

    # Data
    def set_data(self, value):
        self.set_value(config.search_result_key_data, value)
    def get_data(self):
        return self.get_value(config.search_result_key_data)

# Asset search result
class AssetSearchResult(SearchResult):

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        super().__init__(json_data, json_platform)

    # Mime
    def set_mime(self, value):
        self.set_value(config.asset_key_mime, value)
    def get_mime(self):
        return self.get_value(config.asset_key_mime)

    # Width
    def set_width(self, value):
        self.set_value(config.asset_key_width, value)
    def get_width(self):
        return self.get_value(config.asset_key_width)

    # Height
    def set_height(self, value):
        self.set_value(config.asset_key_height, value)
    def get_height(self):
        return self.get_value(config.asset_key_height)

    # Duration
    def set_duration(self, value):
        self.set_value(config.asset_key_duration, value)
    def get_duration(self):
        return self.get_value(config.asset_key_duration)
