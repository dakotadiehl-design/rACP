# acp-sim

Python-only simulator and Remote demo. It is not a Rust/Swift production authority.

```bash
python3 -m acp sim bridge --listen 127.0.0.1:27421
python3 -m acp sim conductor --connect ws://127.0.0.1:27421/acp
python3 -m acp remote controls
python3 -m acp remote go
python3 -m acp remote hold fog_burst --seconds 3
python3 -m acp remote disconnect --dirty
```
