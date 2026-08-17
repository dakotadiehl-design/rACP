# ACP Wireshark dissector

Lua plugin: `acp.lua`

## Install

Copy `acp.lua` into your Wireshark personal plugins directory, or run:

```bash
python3 scripts/install-wireshark-dissector.sh
```

Typical locations:

- macOS: `~/.local/lib/wireshark/plugins` or `~/.config/wireshark/plugins`
- Linux: `~/.local/lib/wireshark/plugins`
- Windows: `%APPDATA%\\Wireshark\\plugins`

## Filters

```
acp
acp.type == "health.heartbeat"
acp.command.status == "rejected"
acp.bridge.blackout
acp.correlation_id == "<uuid>"
```

Discovery UDP is recognized on port 27420 via the `ACP0` magic.

Optional coloring: load `acp-coloring-rules.txt`.
