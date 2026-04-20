# secretfence

**Your AI coding assistant can read your `.env` file. secretfence stops it.**

A fully local CLI that detects secrets in your project and protects them from AI coding tools — through ignore files, real-time hook scanning, and OS-level process sandboxing. No accounts. No API calls. No network access. Everything runs on your machine.

## Why This Exists

Every AI coding tool can read every file in your project. Your `.env`, your private keys, your deploy secrets — all of it goes into the LLM's context window. The ecosystem response so far:

| Tool | What it does | Fully local? | Enforced? |
|------|-------------|:------------:|:---------:|
| `.cursorignore` / `.claudeignore` / etc. | Ask the AI not to read certain files | Yes | No — agent mode can bypass via shell |
| [aiignore-cli](https://github.com/yjcho9317/aiignore-cli) | Generate ignore files for all AI tools | Yes | No — same bypass problem |
| [ggshield ai-hook](https://github.com/GitGuardian/ggshield) | Real-time hook scanning | **No** — requires GitGuardian API | Partial — hooks are advisory |
| [.llmignore](https://github.com/llmignore-spec/llmignore-spec) | Universal ignore file spec | Yes (spec only) | No — no tool enforces it yet |
| Secret managers (1Password, Vault, etc.) | Remove secrets from disk entirely | Yes | Yes — but requires infra changes |

**The gap:** No tool offers fully local, real-time secret scanning with OS-level enforcement. secretfence does.

## Three Layers of Protection

```
Layer 1: SCAN          Layer 2: HOOK           Layer 3: SANDBOX
─────────────────      ─────────────────       ─────────────────
Detect secrets         Real-time scanning      OS-level isolation
Generate ignore files  Block before AI reads   Kernel-enforced deny
                       <50ms per check         Cannot be bypassed

sf scan --fix          sf hook install         sf exec -- claude
```

Each layer works independently. Use one, two, or all three.

## Quick Start

```bash
# Install
cargo install secretfence

# Scan your project for exposed secrets
sf scan

# Auto-generate ignore files for all detected AI tools
sf scan --fix

# Install real-time hooks (Claude Code, Cursor, Gemini CLI, etc.)
sf hook install

# Run your AI tool in a sandboxed process
sf exec -- claude
```

## Layer 1: Scan + Generate

Detect secret files and content patterns, then generate the right ignore config for every AI tool in your project.

```
$ sf scan

  secretfence v0.1.0 — scanning project...

  SECRETS FOUND:

  .env                        dotenv file (environment variables)
  .env.local                  dotenv file (environment variables)
  deploy-key.pem              private key file
  foundry.toml                web3 config (may contain private keys/RPC URLs)

  CONTENT MATCHES:

  hardhat.config.ts:12        Ethereum private key (64 hex chars)
  src/config.ts:45            AWS Access Key ID

  Found 6 secrets in 5 files.

  Run `sf scan --fix` to generate ignore files for your AI tools.
```

```
$ sf scan --fix

  Generated ignore rules for:
    Claude Code    .claude/settings.json (6 deny rules added)
    Cursor         .cursorignore (6 patterns added)
    Gemini CLI     .geminiignore (6 patterns added)
    Universal      .llmignore (6 patterns added)
```

### Supported AI Tools

| AI Tool | Ignore file | `scan --fix` | `hook install` |
|---------|------------|:------------:|:--------------:|
| Claude Code | `.claude/settings.json` | Yes | Yes |
| Cursor | `.cursorignore` | Yes | Yes |
| Gemini CLI | `.geminiignore` | Yes | Yes |
| JetBrains AI | `.aiignore` | Yes | Planned |
| Windsurf | `.codeiumignore` | Yes | Planned |
| Aider | `.aiderignore` | Yes | Planned |
| GitHub Copilot | (no ignore file) | N/A | Planned |
| Universal | `.llmignore` | Yes | N/A |

## Layer 2: Hook Scanning

Install real-time hooks that scan every file read, file write, and shell command before the AI executes it. Fully local pattern matching — nothing leaves your machine.

```
$ sf hook install

  Installed hooks for:
    Claude Code    PreToolUse hook → sf hook check --format claude
    Cursor         Pre-prompt hook → sf hook check --format cursor

  Hooks scan for 800+ secret patterns in <50ms per check.
```

When the AI tries to read a secret file:
```
  [secretfence] BLOCKED: Read access to .env
  Rule: dotenv — Environment variable files contain secrets
  Run `sf rules list` to see all active rules.
```

## Layer 3: Process Sandbox

Run your AI tool inside an OS-level sandbox that physically prevents it from reading secret files. Even if the AI runs `cat .env` through a shell command, the kernel denies the read.

```bash
# Auto-detect secrets and sandbox the process
sf exec -- claude

# Use a preset profile
sf exec --profile web3 -- cursor

# Explicit deny list
sf exec --deny .env,.env.local,deploy-key.pem -- claude

# Preview what would be sandboxed
sf exec --dry-run -- claude
```

### Platform Support

| Platform | Mechanism | Enforcement |
|----------|-----------|-------------|
| macOS | `sandbox-exec` (Seatbelt profiles) | Kernel-enforced file read denial |
| Linux | Landlock LSM (kernel 5.13+) | Kernel-enforced file read denial |
| Windows | Env var scrubbing + auto-generated ignore files + hooks | Best-effort (no kernel sandbox) |

On macOS and Linux, the AI process gets `EPERM` (Permission Denied) when it tries to open a denied file — regardless of whether it uses `cat`, `python`, `node`, or any other binary. This cannot be bypassed from userspace.

## Profiles

Built-in presets for common ecosystems:

**`web3`** — Foundry, Hardhat, blockchain development:
```bash
sf exec --profile web3 -- claude
# Denies: .env*, foundry.toml, hardhat.config.*, *.pem, mnemonic.txt
# Scrubs: PRIVATE_KEY, MNEMONIC, DEPLOYER_*, ETHERSCAN_*, ALCHEMY_*, INFURA_*
```

**`generic`** — Common patterns across all ecosystems:
```bash
sf exec --profile generic -- claude
# Denies: .env*, *.pem, *.key, credentials.*, secrets.*, terraform.tfvars
# Scrubs: *_SECRET, *_KEY, *_TOKEN, *_PASSWORD, DATABASE_URL
```

Create custom profiles in `.secretfencerc`.

## Configuration

Create a `.secretfencerc` in your project root:

```toml
# Default profile for `sf exec`
profile = "web3"

# Additional secret paths (merged with builtins)
[rules]
extra_deny_paths = ["my-custom-secrets.yaml", "deploy-keys/"]
extra_deny_env = ["MY_APP_MASTER_KEY"]

# Files that should NOT be flagged
[rules.allow]
paths = [".env.example", "test/fixtures/.env.test"]

# Custom content detection rules
[[rules.custom]]
id = "internal-api-key"
description = "Internal API key format"
regex = "INTERNAL_[A-Z]+_KEY=[A-Za-z0-9]{32}"
```

## Detection

secretfence ships with 800+ content patterns (ported from [gitleaks](https://github.com/gitleaks/gitleaks)) and 50+ file path patterns covering:

- **Cloud:** AWS, GCP, Azure credentials
- **Web3:** Private keys, mnemonics, RPC URLs, Etherscan keys
- **Databases:** Connection strings, Redis URLs
- **Auth:** JWTs, OAuth tokens, API keys
- **Infrastructure:** Terraform secrets, Docker configs, CI/CD tokens
- **Languages:** `.npmrc`, `.pypirc`, `gem credentials`, Cargo tokens
- **Certificates:** PEM, P12, PFX, SSH keys

All detection runs locally using precompiled regex. No network calls, no API keys, no accounts.

## How It Compares

| | secretfence | ggshield ai-hook | aiignore-cli | .llmignore |
|---|:-----------:|:----------------:|:------------:|:----------:|
| Fully local | Yes | No | Yes | Yes |
| Real-time hook scanning | Yes | Yes | No | No |
| OS-level sandboxing | Yes | No | No | No |
| Content pattern matching | 800+ rules | 500+ rules | No | No |
| File path detection | 50+ patterns | No | Yes | No |
| Ignore file generation | All tools | No | All tools | Single spec |
| Custom rules | `.secretfencerc` | GG dashboard | `.aiignorerc` | N/A |
| Secret validation (live check) | No | Yes | No | No |
| Requires account | No | Yes | No | No |
| Language | Rust | Python | Node.js | Spec |

**Where secretfence is weaker:**
- No live secret validation (ggshield can check if an AWS key is actually active)
- Newer pattern database (ggshield has years of false-positive tuning)
- No CI/CD integrations yet (ggshield has GitHub Actions, pre-commit, etc.)
- macOS sandbox-exec is deprecated by Apple (still works, but no guarantees for future OS versions)

## Contributing

Contributions welcome. Areas where help is most needed:

- Additional AI tool hook integrations
- Content detection rules for ecosystems we're missing
- Windows sandbox improvements
- CI/CD integrations (GitHub Actions, pre-commit hooks)

```bash
git clone https://github.com/Cyfrin/secretfence
cd secretfence
cargo build
cargo test
```

## License

MIT
