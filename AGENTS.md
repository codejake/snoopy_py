# AGENTS.md

## Project Overview

This repository contains a single-user-facing script, [snoopy.py](/Users/jshaw/Projects/snoopy_py/snoopy.py:1), plus `uv` project metadata in [pyproject.toml](/Users/jshaw/Projects/snoopy_py/pyproject.toml:1).

`snoopy.py` is a passive local-network reconnaissance dashboard. It:

- launches `tcpdump`
- reads pcap bytes from stdout
- decodes several discovery/routing protocols
- displays aggregated discoveries in a Textual TUI
- can save the current device list to JSON

## Working Agreements

- Preserve the passive nature of the tool unless the user explicitly asks for active scanning behavior.
- Keep `pyproject.toml` and the inline `uv` script metadata in `snoopy.py` aligned when changing Python or dependency requirements.
- Treat `tcpdump` as a required external dependency. It is not managed by `uv`.
- Prefer small, surgical edits. This repo is intentionally compact.

## Environment Expectations

- Python target: `3.13`
- Python dependency manager: `uv`
- Python runtime dependency: `textual>=8.2.8`
- System dependency: `tcpdump`
- Supported platforms: macOS and Linux

## Useful Commands

Sync the local environment:

```bash
uv sync
```

Run the app:

```bash
uv run snoopy.py
```

Run with privileges when needed for packet capture:

```bash
sudo uv run snoopy.py
```

Syntax check:

```bash
python3 -m py_compile snoopy.py
```

## Verification Guidance

For most changes, use the lightest verification that proves the edit:

- `python3 -m py_compile snoopy.py` for syntax safety
- `uv run snoopy.py --help` when dependency resolution is available
- a live run only when the change affects capture behavior or TUI behavior

Be careful with automated tests or runs that assume packet-capture permissions. Those may require `sudo` or fail in sandboxed environments.

## Common Change Areas

- CLI and startup flow: `build_parser()`, `main()`, interface detection helpers
- capture lifecycle: `CaptureSession`
- TUI behavior and save action: `SnoopyDashboard`
- protocol decoding: `decode_*` helpers and packet parsing functions

## Documentation Expectations

When updating docs:

- mention that Snoopy is passive
- document the `tcpdump` dependency clearly
- include `uv` setup and run commands
- keep keyboard shortcuts in sync with the app bindings
