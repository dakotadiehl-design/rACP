-- Aurora Communications Protocol Wireshark Lua dissector
-- UDP discovery on 27420 (ACP0 framed) and optional decode-as on TCP.

local acp = Proto("acp", "Aurora Communications Protocol")

local f_magic = ProtoField.string("acp.magic", "Magic")
local f_dver = ProtoField.uint8("acp.datagram_version", "Datagram version")
local f_enc = ProtoField.uint8("acp.encoding", "Encoding")
local f_version = ProtoField.string("acp.version", "Protocol version")
local f_type = ProtoField.string("acp.type", "Message type")
local f_message_id = ProtoField.string("acp.message_id", "Message ID")
local f_correlation_id = ProtoField.string("acp.correlation_id", "Correlation ID")
local f_causation_id = ProtoField.string("acp.causation_id", "Causation ID")
local f_session_id = ProtoField.string("acp.session_id", "Session ID")
local f_sequence = ProtoField.uint64("acp.sequence", "Sequence")
local f_qos = ProtoField.string("acp.qos", "QoS")
local f_src_node = ProtoField.string("acp.source.node_id", "Source node")
local f_src_comp = ProtoField.string("acp.source.component_id", "Source component")
local f_dst_node = ProtoField.string("acp.destination.node_id", "Destination node")
local f_cmd_status = ProtoField.string("acp.command.status", "Command status")
local f_state_res = ProtoField.string("acp.state.resource", "State resource")
local f_state_rev = ProtoField.uint64("acp.state.revision", "State revision")
local f_state_conf = ProtoField.string("acp.state.confidence", "State confidence")
local f_health = ProtoField.string("acp.health.status", "Health status")
local f_error = ProtoField.string("acp.error.code", "Error code")
local f_show_id = ProtoField.string("acp.show.id", "Show ID")
local f_show_rev = ProtoField.uint64("acp.show.revision", "Show revision")
local f_asset_id = ProtoField.string("acp.asset.id", "Asset ID")
local f_asset_status = ProtoField.string("acp.asset.status", "Asset status")
local f_participant = ProtoField.string("acp.participant.id", "Participant ID")
local f_xfer = ProtoField.string("acp.resource.transfer_id", "Transfer ID")
local f_blackout = ProtoField.bool("acp.bridge.blackout", "Bridge blackout")

acp.fields = {
  f_magic, f_dver, f_enc, f_version, f_type, f_message_id, f_correlation_id,
  f_causation_id, f_session_id, f_sequence, f_qos, f_src_node, f_src_comp,
  f_dst_node, f_cmd_status, f_state_res, f_state_rev, f_state_conf, f_health,
  f_error, f_show_id, f_show_rev, f_asset_id, f_asset_status, f_participant,
  f_xfer, f_blackout
}

local udp_port = DissectorTable.get("udp.port")

local function add_json_fields(tree, buf, json)
  if type(json) ~= "table" then return end
  if json.acp then tree:add(f_version, json.acp) end
  if json.type then tree:add(f_type, json.type) end
  if json.message_id then tree:add(f_message_id, json.message_id) end
  if json.correlation_id then tree:add(f_correlation_id, json.correlation_id) end
  if json.causation_id then tree:add(f_causation_id, json.causation_id) end
  if json.session_id then tree:add(f_session_id, json.session_id) end
  if json.sequence then tree:add(f_sequence, json.sequence) end
  if json.qos then tree:add(f_qos, json.qos) end
  if type(json.source) == "table" then
    if json.source.node_id then tree:add(f_src_node, json.source.node_id) end
    if json.source.component_id then tree:add(f_src_comp, json.source.component_id) end
  end
  if type(json.destination) == "table" and json.destination.node_id then
    tree:add(f_dst_node, json.destination.node_id)
  end
  local p = json.payload
  if type(p) == "table" then
    if p.status and json.type == "command.ack" then tree:add(f_cmd_status, p.status) end
    if p.resource then tree:add(f_state_res, p.resource) end
    if p.revision then tree:add(f_state_rev, p.revision) end
    if p.confidence then tree:add(f_state_conf, p.confidence) end
    if p.status and json.type == "health.heartbeat" then tree:add(f_health, p.status) end
    if p.code then tree:add(f_error, p.code) end
    if p.enabled ~= nil and json.type == "bridge.blackout" then
      tree:add(f_blackout, p.enabled)
    end
    if type(p.show) == "table" then
      if p.show.show_id then tree:add(f_show_id, p.show.show_id) end
      if p.show.revision then tree:add(f_show_rev, p.show.revision) end
    end
    if p.transfer_id then tree:add(f_xfer, p.transfer_id) end
    if p.participant_id then tree:add(f_participant, p.participant_id) end
    if p.asset_id then tree:add(f_asset_id, p.asset_id) end
    if p.state then tree:add(f_asset_status, p.state) end
  end
end

function acp.dissector(buf, pinfo, tree)
  if buf:len() < 6 then return end
  if buf(0, 4):string() ~= "ACP0" then return end
  pinfo.cols.protocol = "ACP"
  local subtree = tree:add(acp, buf(), "Aurora Communications Protocol")
  subtree:add(f_magic, buf(0, 4))
  subtree:add(f_dver, buf(4, 1))
  subtree:add(f_enc, buf(5, 1))
  local enc = buf(5, 1):uint()
  local payload = buf(6):bytes():raw()
  pinfo.cols.info = "ACP discovery"
  if enc == 1 then
    -- JSON diagnostic discovery
    local ok, obj = pcall(function()
      -- Wireshark may not have a JSON decoder; show raw
      return nil
    end)
    subtree:add(buf(6), "JSON payload")
  else
    subtree:add(buf(6), "CBOR payload")
  end
end

udp_port:add(27420, acp)
