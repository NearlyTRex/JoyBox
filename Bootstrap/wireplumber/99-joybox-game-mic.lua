-- Managed by JoyBox Bootstrap (wireplumber). Edits are overwritten.
-- Keeps Wine and Proton game recordings on the silent game mic, except allowed
-- games and protected apps (comma-separated, matched by binary or app name).
load_script("joybox-game-mic.lua", {
  ["mic.node-name"] = "joybox_game_mic",
  ["allow"] = "${allow}",
  ["protect"] = "${protect}",
})
