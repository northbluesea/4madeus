# 4madeus

**Zero-noise security scanner, deterministic lockfile (`4madeus.lock`), and real-time `stdio` proxy for MCP servers and AI agents.**

`4madeus` prevents **Shadow MCP**, **hardcoded API key leaks**, and **tool poisoning (rug-pull) attacks** across Cursor, Claude Desktop, Claude Code, VS Code, and Windsurf without slowing down your workflow.

## Why 4madeus?

- **Instant Shadow MCP Discovery (`4madeus scan`):** Scans all local AI client configs in `<5ms` and flags exposed credentials or unpinned `npx`/`uvx` packages.
- **Deterministic Tool Pinning (`4madeus.lock`):** Like `package-lock.json` for AI tools. Computes a canonical SHA-256 hash of every tool definition (`name`, `description`, `inputSchema`). Commit `4madeus.lock` to Git so your team stays protected.
- **Real-Time Quarantine Proxy (`4madeus run`):** Wraps MCP `stdio` streams in Rust with `<1ms` overhead. Blocks unauthorized reads to `~/.ssh`, `.env`, or `.aws/credentials` and quarantines individual tools if their definition changes silently.

## Quickstart

    # 1. Scan your machine (read-only)
    npx 4madeus scan

    # 2. Create 4madeus.lock in your repository
    4madeus init

    # 3. Wrap local MCP client configs (creates .bak backups)
    4madeus init --wrap

    # Revert anytime
    4madeus unwrap

## Build from Source

    git clone https://github.com/northbluesea/4madeus.git
    cd 4madeus
    cargo build --release

## License

MIT