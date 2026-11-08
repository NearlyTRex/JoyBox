-- Managed by JoyBox Bootstrap (wireplumber). Edits are overwritten.
-- Pins every recording stream of a Wine or Proton game to the silent game mic,
-- unless the game is allowed the real mic or the app is protected.
-- The pin is the default metadata's target.object, which the policy prefers over
-- the device a game asks for, and it is set again whenever anything moves the stream.

local config = ... or {}
local mic_name = config["mic.node-name"] or "joybox_game_mic"

-- Lowercased names from a comma-separated list
function toNameSet (text)
  local set = {}
  for item in (text or ""):gmatch ("[^,]+") do
    item = item:match ("^%s*(.-)%s*$"):lower ()
    if item ~= "" then
      set[item] = true
    end
  end
  return set
end

local allowed = toNameSet (config["allow"])
local protected = toNameSet (config["protect"])

local metadata_om = ObjectManager {
  Interest { type = "metadata", Constraint { "metadata.name", "=", "default" } }
}
local mics_om = ObjectManager {
  Interest { type = "node", Constraint { "node.name", "=", mic_name } }
}
local streams_om = ObjectManager {
  Interest { type = "node", Constraint { "media.class", "=", "Stream/Input/Audio" } }
}

function isListed (set, props)
  local binary = (props["application.process.binary"] or ""):lower ()
  local name = (props["application.name"] or ""):lower ()
  return set[binary] ~= nil or set[name] ~= nil
end

function isGameStream (props)
  local binary = props["application.process.binary"] or ""
  local name = props["application.name"] or ""
  return binary:find("wine", 1, true) ~= nil or name:lower():match("%.exe$") ~= nil
end

function shouldPin (props)
  return isGameStream (props) and not isListed (allowed, props) and not isListed (protected, props)
end

function pinStream (stream)
  if not shouldPin (stream.properties) then
    return
  end
  local mic = mics_om:lookup ()
  local metadata = metadata_om:lookup ()
  if mic == nil or metadata == nil then
    return
  end
  local serial = mic.properties["object.serial"]
  if metadata:find (stream["bound-id"], "target.object") == serial then
    return
  end
  Log.info (stream, "pinning " .. (stream.properties["application.name"] or "game") .. " to " .. mic_name)
  metadata:set (stream["bound-id"], "target.object", "Spa:Id", serial)
end

function pinAllStreams ()
  for stream in streams_om:iterate () do
    pinStream (stream)
  end
end

streams_om:connect ("object-added", function (_, stream)
  pinStream (stream)
end)

mics_om:connect ("object-added", function ()
  pinAllStreams ()
end)

metadata_om:connect ("object-added", function (_, metadata)
  metadata:connect ("changed", function (_, subject, key)
    if key ~= "target.object" and key ~= "target.node" then
      return
    end
    local stream = streams_om:lookup {
      Constraint { "bound-id", "=", subject, type = "gobject" }
    }
    if stream ~= nil then
      pinStream (stream)
    end
  end)
  pinAllStreams ()
end)

metadata_om:activate ()
mics_om:activate ()
streams_om:activate ()
