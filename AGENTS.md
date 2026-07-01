# AGENTS.md

## Project Overview

This repository is intentionally compact. It centers on the single user-facing script `snoopy.py` plus `uv` project metadata in `pyproject.toml`.

`snoopy.py` is a passive local-network reconnaissance dashboard. It:

- launches `tcpdump`
- reads pcap bytes from stdout
- decodes discovery and routing protocols
- displays aggregated discoveries in a Textual TUI
- can save the current device list to JSON

## Working Agreements

- Preserve the passive nature of the tool unless the user explicitly asks for active scanning behavior.
- Prefer small, surgical edits over broad refactors.
- Preserve existing project conventions unless explicitly asked to change them.
- Keep `pyproject.toml` and the inline `uv` script metadata in `snoopy.py` aligned when changing Python or dependency requirements.
- Treat `tcpdump` as a required external dependency. It is not managed by `uv`.
- Minimize third-party dependencies and justify any new dependency before adding it.

## Git
- Create one commit per completed task or logical change.
- Use clear commit messages that describe what changed and why.
- For commits made by the agent, append the trailer `Coauthored-by: Codex <noreply@openai.com>`.

## Environment Expectations

- Python target: `3.13`
- Python dependency manager: `uv`
- Python runtime dependency: `textual>=8.2.8`
- System dependency: `tcpdump`
- Supported platforms: macOS and Linux

## Code Standards

- Write production-quality Python that is clear, maintainable, and minimally complex.
- Use type hints for public functions and any non-trivial internal functions.
- Write docstrings for public modules, classes, and functions.
- Comment code only where intent or behavior is not obvious.
- Prefer standard library solutions unless a third-party dependency is clearly justified.
- Handle errors explicitly and surface actionable error messages.
- Do not swallow exceptions silently.
- Validate inputs early and fail predictably.

## Tooling And Validation

Use `uv` for Python environment and dependency management.

Useful commands:

```bash
uv sync
uv run snoopy.py
sudo uv run snoopy.py
python3 -m py_compile snoopy.py
```

Validation guidance:

- Use the lightest verification that proves the edit.
- `python3 -m py_compile snoopy.py` is the default syntax check.
- `uv run snoopy.py --help` is useful when dependency resolution is available.
- Run a live capture only when the change affects capture behavior or TUI behavior.
- Be careful with checks that assume packet-capture permissions; they may require `sudo` or fail in sandboxed environments.
- Run `ruff check` on changed Python files when available.
- If formatting is needed, run `ruff format` on changed Python files.
- If `uv`, `ruff`, or any other relevant validation cannot be run, say so clearly.

## Common Change Areas

- CLI and startup flow: `build_parser()`, `main()`, interface detection helpers
- capture lifecycle: `CaptureSession`
- TUI behavior and save action: `SnoopyDashboard`
- protocol decoding: `decode_*` helpers and packet parsing functions

## Safety

- Do not revert, overwrite, or reformat unrelated user changes.
- Do not modify unrelated files.
- Do not make destructive git changes unless explicitly requested.
- Do not store secrets in code.
- Do not leak machine-specific local filesystem paths into tracked files in this repo.
- Use portable references such as repo-relative paths or plain filenames instead of absolute local paths.

## Documentation Expectations

When updating docs:

- mention that Snoopy is passive
- document the `tcpdump` dependency clearly
- include `uv` setup and run commands
- keep keyboard shortcuts in sync with the app bindings

## Final Response

- Summarize the change briefly.
- Mention what validation was run.
- Call out any known limitations, follow-ups, or risks.
