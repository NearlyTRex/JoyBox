# Imports
import json

LEGENDARY = ["/tools/python", "/tools/legendary"]


def legendary_list(*games):
    return json.dumps([dict(game) for game in games])


def listed_game(app_name, title, build = None):
    game = {"app_name": app_name, "app_title": title, "asset_infos": {}}
    if build is not None:
        game["asset_infos"]["Windows"] = {"build_version": build}
    return game


def legendary_info(**game):
    return json.dumps({"game": game, "install": {}, "manifest": {}})
