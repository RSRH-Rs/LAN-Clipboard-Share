# ClipboardShare

A tiny tool that **auto-discovers peers on your LAN** and **syncs the clipboard**.  
Text works on all platforms; **image sync is Windows-only**.

## Features

- **Zero-config discovery** (UDP broadcast finds devices on the same subnet)
- **Text & (Windows) image** clipboard sync
- **Pure Python**, single-file run

## Requirements

- Python **3.9+**

## Install

```bash
pip install -r requirements.txt
```

## Quick Start

1. Adjust `config.py` if needed (ports, broadcast interval, protocol constants).
2. Run on two (or more) machines in the same LAN:
   ```bash
   python autoclipshare.py
   ```

## Log messages

- **Sent:** `Sent Text Update` / `Sent Text Update`
- **Received:** `Recived Text Update` / `Recived Image Update`

## Notes

- Non-Windows platforms do **not** write images to the system clipboard yet (you’ll see a notice). Text is unaffected.
- Designed for **trusted LANs** only; there’s **no end-to-end encryption**. Avoid use on public networks.
