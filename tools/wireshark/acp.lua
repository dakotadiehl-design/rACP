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
local f_remote_id = ProtoField.string("acp.remote.id", "Remote ID")
local f_remote_device = ProtoField.string("acp.remote.device_id", "Remote device ID")
local f_remote_part = ProtoField.string("acp.remote.participant_id", "Remote participant ID")
local f_remote_layout = ProtoField.string("acp.remote.layout.id", "Remote layout ID")
local f_remote_layout_rev = ProtoField.uint64("acp.remote.layout.revision", "Remote layout revision")
local f_remote_control = ProtoField.string("acp.remote.control.id", "Remote control ID")
local f_remote_ctype = ProtoField.string("acp.remote.control.type", "Remote control type")
local f_remote_ix = ProtoField.string("acp.remote.control.interaction", "Remote interaction")
local f_remote_inv = ProtoField.string("acp.remote.control.invocation_id", "Remote invocation ID")
local f_remote_value = ProtoField.string("acp.remote.control.value", "Remote control value")
local f_remote_perm = ProtoField.string("acp.remote.permission", "Remote permission")
local f_remote_ready = ProtoField.string("acp.remote.readiness", "Remote readiness")
local f_remote_lease = ProtoField.string("acp.remote.momentary.lease_id", "Momentary lease ID")
local f_remote_exp = ProtoField.uint64("acp.remote.momentary.expires_ms", "Momentary expires ms")
local f_security_mode = ProtoField.string("acp.security.auth_mode", "Authentication mode")
local f_security_state = ProtoField.string("acp.security.state", "Principal/enrollment state")
local f_security_domain = ProtoField.string("acp.security.trust_domain_id", "Trust domain ID")
local f_security_credential = ProtoField.string("acp.security.credential_id", "Credential ID")
local f_security_key = ProtoField.string("acp.security.identity_key_id", "Identity key ID")
local f_security_enrollment = ProtoField.string("acp.security.enrollment_id", "Enrollment ID")
local f_security_attempt = ProtoField.string("acp.security.attempt_id", "Enrollment attempt ID")
local f_security_suite = ProtoField.string("acp.security.suite", "Security suite")
local f_security_revocation = ProtoField.string("acp.security.revocation_state", "Revocation state")
local f_security_policy_revision = ProtoField.uint64("acp.security.policy_revision", "Policy revision")

acp.fields = {
  f_magic, f_dver, f_enc, f_version, f_type, f_message_id, f_correlation_id,
  f_causation_id, f_session_id, f_sequence, f_qos, f_src_node, f_src_comp,
  f_dst_node, f_cmd_status, f_state_res, f_state_rev, f_state_conf, f_health,
  f_error, f_show_id, f_show_rev, f_asset_id, f_asset_status, f_participant,
  f_xfer, f_blackout, f_remote_id, f_remote_device, f_remote_part, f_remote_layout,
  f_remote_layout_rev, f_remote_control, f_remote_ctype, f_remote_ix, f_remote_inv,
  f_remote_value, f_remote_perm, f_remote_ready, f_remote_lease, f_remote_exp,
  f_security_mode, f_security_state, f_security_domain, f_security_credential,
  f_security_key, f_security_enrollment, f_security_attempt, f_security_suite,
  f_security_revocation, f_security_policy_revision
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
    -- Deliberately expose only public identifiers/state. Never add PAKE shares,
    -- confirmations, bindings, ciphertext, signatures, credentials, or key bytes.
    if p.auth_mode then tree:add(f_security_mode, p.auth_mode) end
    if type(p.auth) == "table" then
      if p.auth.mode then tree:add(f_security_mode, p.auth.mode) end
      if p.auth.trust_domain_id then tree:add(f_security_domain, p.auth.trust_domain_id) end
      if p.auth.credential_id then tree:add(f_security_credential, p.auth.credential_id) end
      if p.auth.identity_key_id then tree:add(f_security_key, p.auth.identity_key_id) end
    end
    if p.principal_state then tree:add(f_security_state, p.principal_state) end
    if p.state and json.type and string.find(json.type, "security.", 1, true) then tree:add(f_security_state, p.state) end
    if p.trust_domain_id then tree:add(f_security_domain, p.trust_domain_id) end
    if p.credential_id then tree:add(f_security_credential, p.credential_id) end
    if p.identity_key_id then tree:add(f_security_key, p.identity_key_id) end
    if p.enrollment_id then tree:add(f_security_enrollment, p.enrollment_id) end
    if p.attempt_id then tree:add(f_security_attempt, p.attempt_id) end
    if p.suite then tree:add(f_security_suite, p.suite) end
    if p.revocation_state then tree:add(f_security_revocation, p.revocation_state) end
    if p.policy_revision then tree:add(f_security_policy_revision, p.policy_revision) end
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
    if type(p.remote) == "table" then
      if p.remote.remote_id then tree:add(f_remote_id, p.remote.remote_id) end
      if p.remote.device_id then tree:add(f_remote_device, p.remote.device_id) end
      if p.remote.participant_id then tree:add(f_remote_part, p.remote.participant_id) end
    end
    if p.remote_id then tree:add(f_remote_id, p.remote_id) end
    if p.control_id then tree:add(f_remote_control, p.control_id) end
    if p.control_type then tree:add(f_remote_ctype, p.control_type) end
    if p.interaction then tree:add(f_remote_ix, p.interaction) end
    if p.invocation_id then tree:add(f_remote_inv, p.invocation_id) end
    if p.value ~= nil then tree:add(f_remote_value, tostring(p.value)) end
    if p.permission then tree:add(f_remote_perm, p.permission) end
    if p.state and json.type and string.find(json.type, "readiness", 1, true) then
      tree:add(f_remote_ready, p.state)
    end
    if p.lease_id then tree:add(f_remote_lease, p.lease_id) end
    if p.expires_ms then tree:add(f_remote_exp, p.expires_ms) end
    if p.layout_id then tree:add(f_remote_layout, p.layout_id) end
    if p.layout_revision then tree:add(f_remote_layout_rev, p.layout_revision) end
    if type(p.layout) == "table" then
      if p.layout.layout_id then tree:add(f_remote_layout, p.layout.layout_id) end
      if p.layout.revision then tree:add(f_remote_layout_rev, p.layout.revision) end
    end
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
