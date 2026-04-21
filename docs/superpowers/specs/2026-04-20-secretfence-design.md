# secretfence — Design Spec

> Fully local, zero-account secret protection for AI coding tools.

## Context

AI coding assistants (Claude Code, Cursor, Copilot, Gemini CLI, etc.) have full filesystem access and can read `.env` files, private keys, and other secrets. Each tool has its own ignore mechanism (`.cursorignore`, `.claudeignore`, `.geminiignore`, etc.) but:

1. **Fragmented** — every tool uses a different file format
2. **Advisory** — agent/terminal modes can bypass ignore files via shell commands (`cat .env`)
3. **No enforcement** — no tool offers OS-level prevention of secret access

The only hook-based scanner (GitGuardian's `ggshield ai-hook`) requires a GitGuardian account and API calls. There is no fully local, self-contained solution.

**secretfence** fills this gap: a single Rust CLI that detects secrets, generates ignore files, installs real-time hook scanners, and optionally sandboxes AI tool processes at the OS level — all fully local, no accounts, no network calls.

## Competitive Landscape

| Capability | secretfence | ggshield ai-hook | aiignore-cli | .llmignore spec |
|------------|-------------|------------------|--------------|-----------------|
| Fully local (no account/API) | Yes | No (GitGuardian API) | Yes | Yes (spec only) |
| Secret file detection | Yes | No (scans content only) | Yes | No |
| Content pattern matching | Yes (800+ rules) | Yes (500+ rules) | No | No |
| Ignore file generation | Yes (all tools) | No | Yes (all tools) | No (universal spec) |
| Hook-based real-time scanning | Yes | Yes (Claude, Cursor, Copilot) | No | No |
| OS-level process sandboxing | Yes (macOS, Linux) | No | No | No |
| Custom rule support | Yes (TOML config) | Yes (via GG dashboard) | Yes (.aiignorerc) | N/A |
| Preset profiles (web3, etc.) | Yes | No | No | No |
| Language | Rust (single binary) | Python (pip install) | Node.js (npx) | Spec + parsers |
| License | MIT | MIT (CLI) + SaaS API | MIT | MIT |

**Honest assessment of weaknesses vs. competitors:**

| Area | secretfence disadvantage |
|------|--------------------------|
| Pattern quality | ggshield's 500+ patterns are battle-tested at scale with real-world false positive tuning. Our ported gitleaks rules may have more noise. |
| Ecosystem integration | ggshield has GitHub Actions, pre-commit, CI/CD integrations. secretfence starts with CLI only. |
| Validation | ggshield validates secrets against live APIs by default. secretfence supports this via `--verify` flag but it's opt-in. |
| Maintenance | GitGuardian has a full team maintaining pattern databases. secretfence relies on community + gitleaks upstream. |
| Ignore file generation | aiignore-cli already does this well and is established. secretfence's Layer 1 is not novel. |
| Windows sandbox | No real enforcement — best-effort env scrubbing only. macOS sandbox-exec is deprecated. |

## Architecture

### Project Structure

```
secretfence/
├── Cargo.toml
├── src/
│   ├── main.rs                   # CLI entry point (clap)
│   ├── cli.rs                    # Command definitions
│   ├── config.rs                 # .secretfencerc loading
│   │
│   ├── scan/                     # Layer 1: Detect + Generate
│   │   ├── mod.rs
│   │   ├── detector.rs           # Secret file/pattern detection
│   │   ├── reporter.rs           # Terminal output formatting
│   │   └── generators/           # Ignore file generators
│   │       ├── mod.rs            # Generator trait + dispatch
│   │       ├── claude.rs         # .claude/settings.json deny rules
│   │       ├── cursor.rs         # .cursorignore
│   │       ├── gemini.rs         # .geminiignore
│   │       ├── jetbrains.rs      # .aiignore
│   │       ├── windsurf.rs       # .codeiumignore
│   │       ├── aider.rs          # .aiderignore
│   │       └── llmignore.rs      # .llmignore (universal)
│   │
│   ├── hook/                     # Layer 2: Real-time Hook Scanning
│   │   ├── mod.rs
│   │   ├── installer.rs          # Install hooks into AI tool configs
│   │   ├── scanner.rs            # Scan hook payloads for secrets
│   │   └── formats/              # Tool-specific payload parsers
│   │       ├── claude.rs
│   │       ├── cursor.rs
│   │       └── copilot.rs
│   │
│   ├── sandbox/                  # Layer 3: Process Isolation
│   │   ├── mod.rs                # Platform detection + dispatch
│   │   ├── macos.rs              # sandbox-exec (Seatbelt profiles)
│   │   ├── linux.rs              # Landlock LSM
│   │   ├── windows.rs            # Best-effort (env scrub + ignore gen)
│   │   └── profiles.rs           # Preset profile loading
│   │
│   └── rules/                    # Detection Rule Engine
│       ├── mod.rs
│       ├── engine.rs             # Regex compilation + matching
│       ├── builtin.toml          # Embedded default rules
│       ├── web3.toml             # Web3-specific rules
│       └── loader.rs             # Custom rule loading
│
├── profiles/                     # Built-in sandbox profiles
│   ├── generic.toml
│   └── web3.toml
│
└── tests/
    ├── scan/
    ├── hook/
    ├── sandbox/
    └── fixtures/                 # Test secret files
```

### CLI Interface

```bash
# Layer 1: Scan + Generate
secretfence scan                        # Detect secrets, print report
secretfence scan --fix                  # Detect + generate ignore files for all AI tools
secretfence scan --fix --tools claude,cursor  # Generate for specific tools only
secretfence scan --json                 # Machine-readable output

# Layer 2: Hook Management
secretfence hook install                # Auto-detect AI tools, install hooks
secretfence hook install --tools claude # Install for specific tool
secretfence hook uninstall              # Remove all secretfence hooks
secretfence hook check                  # Called by hooks — scan stdin payload, exit 0/2

# Layer 3: Sandboxed Execution
secretfence exec -- claude              # Run claude in sandbox (auto-detect secrets)
secretfence exec --profile web3 -- cursor  # Use web3 preset
secretfence exec --deny .env,.env.local -- claude  # Explicit deny list
secretfence exec --dry-run -- claude    # Show what would be sandboxed, don't run

# Config
secretfence init                        # Create .secretfencerc with sensible defaults
secretfence rules list                  # Show all active rules
secretfence rules test .env             # Test if a file would be flagged
```

## Layer 1: Scan + Generate

### Detection Engine

Two types of rules, both evaluated during a scan:

**Path rules** — match file paths against glob patterns:
```toml
[[path_rules]]
id = "dotenv"
description = "Environment variable files"
patterns = [".env", ".env.*", "!.env.example", "!.env.sample"]

[[path_rules]]
id = "private-keys"
description = "Private key files"
patterns = ["*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519"]

[[path_rules]]
id = "web3-config"
description = "Web3 config files that often contain private keys or RPC URLs"
patterns = ["foundry.toml", "hardhat.config.*", ".secret", "mnemonic.txt"]
```

Ships with ~50 built-in path patterns covering: Node, Python, Go, Rust, Ruby, .NET, Java, Solidity/Foundry, Terraform/IaC, mobile (iOS/Android), cloud (AWS/GCP/Azure).

**Content rules** — regex patterns matched against file contents (ported from gitleaks TOML format):
```toml
[[content_rules]]
id = "aws-access-key"
description = "AWS Access Key ID"
regex = '(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
entropy = 3.5

[[content_rules]]
id = "eth-private-key"
description = "Ethereum private key (64 hex chars)"
regex = '(?i)(private[_-]?key|priv[_-]?key)\s*[:=]\s*["\']?(0x)?[0-9a-f]{64}'

[[content_rules]]
id = "mnemonic-phrase"
description = "BIP39 mnemonic seed phrase (12 or 24 words)"
regex = '(?i)(mnemonic|seed[_-]?phrase)\s*[:=]\s*["\']?(\w+\s+){11,23}\w+'
```

**Entropy detection:** Optional per-rule. Calculates Shannon entropy of the matched string. High entropy (>3.5) suggests a real secret vs. a placeholder. Used to reduce false positives on patterns that also match non-secret strings.

### Ignore File Generation

Each generator implements a trait:
```rust
trait IgnoreGenerator {
    fn tool_name(&self) -> &str;
    fn is_installed(&self) -> bool;       // Detect if this AI tool is present
    fn config_path(&self) -> PathBuf;     // Where to write the ignore config
    fn generate(&self, paths: &[SecretPath]) -> String;  // Render ignore content
    fn apply(&self, paths: &[SecretPath]) -> Result<()>;  // Write to disk
}
```

For Claude Code, the generator writes deny rules to `.claude/settings.json`. For Cursor, it writes `.cursorignore`. Each tool has quirks (Cursor uses gitignore syntax, Claude uses JSON arrays, JetBrains uses a different format) — the generators abstract this.

`--fix` only writes files that don't already exist or appends rules that are missing. It never overwrites user customizations.

## Layer 2: Hook-based Scanning

### Installation

`secretfence hook install` detects installed AI tools and registers secretfence as a hook:

**Claude Code:** Adds to `.claude/settings.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Edit|Write|Bash",
        "hook": "secretfence hook check --format claude"
      }
    ]
  }
}
```

**Cursor:** Uses Cursor's hook/rules system to run secretfence before file operations.

**Gemini CLI:** Adds to `.gemini/settings.json` hook configuration.

### Scan Flow

When an AI tool triggers the hook:

```
1. AI tool passes payload via stdin (JSON with tool name, arguments, file paths)
2. secretfence hook check --format <tool> reads stdin
3. Parses tool-specific payload format
4. Extracts file paths and content from the payload
5. Runs content rules against any text content
6. Checks file paths against path rules
7. Exit 0 → clean, AI tool proceeds
   Exit 2 → blocked, prints human-readable warning to stderr
```

**Performance target:** <50ms per check. Achieved via:
- Precompiled regex set (compiled once at binary build time via `regex::RegexSet`)
- No disk I/O during hook checks (rules embedded in binary)
- Streaming stdin parse (no full payload buffering for large payloads)

### What Gets Intercepted

| AI tool action | Hook fires | secretfence checks |
|---------------|-----------|-------------------|
| Read a file | PreToolUse (Read) | Is the file path a known secret file? |
| Write a file | PreToolUse (Write/Edit) | Does the content contain secret patterns? |
| Run a shell command | PreToolUse (Bash) | Does the command access secret files? (`cat .env`, `echo $KEY`) |
| Send a prompt | PrePrompt (where supported) | Does the prompt text contain pasted secrets? |

## Layer 3: Process Isolation (Sandbox)

### macOS: sandbox-exec (Seatbelt)

Generated profile example:
```scheme
(version 1)
(allow default)

;; Deny read access to secret files
(deny file-read*
  (literal "/Users/hunter/project/.env")
  (literal "/Users/hunter/project/.env.local")
  (regex #"/Users/hunter/project/.*\.pem$")
  (literal "/Users/hunter/project/foundry.toml"))

;; This blocks ALL reads to these paths, regardless of which binary
;; (cat, head, python, node, etc.) — the deny is on the file, not the process
```

Launched via: `sandbox-exec -f <profile-path> -- <command>`

**Limitations:**
- `sandbox-exec` is deprecated by Apple (but still works on macOS 15+)
- Profile language (SBPL) is undocumented — we use known-working patterns
- Blocks file reads at the kernel level — applies to all binaries (`cat`, `node`, `python`, etc.) not just the AI tool itself

### Linux: Landlock LSM

Landlock is allow-list based. The strategy:
1. Create a ruleset handling `ReadFile` and `ReadDir` access
2. Add allow rules for the project directory
3. Do NOT add allow rules for secret file paths
4. Call `restrict_self()` — the process can now read everything except the secret files
5. `exec()` the AI tool — it inherits the restrictions

```rust
// Pseudocode
let ruleset = RulesetCreated::new()
    .handle_access(AccessFs::ReadFile | AccessFs::ReadDir)?;

// Allow reading the project directory
ruleset.add_rule(PathBeneath::new(project_dir, AccessFs::ReadFile | AccessFs::ReadDir))?;

// Secret files are excluded by not adding allow rules for them.
// When the process tries to read .env, Landlock denies it.

ruleset.restrict_self()?;
exec(command)?;
```

Note: This is simplified. In practice, Landlock applies to the entire filesystem, so we need to allow system paths (`/usr`, `/lib`, etc.) while restricting only the specific secret files. The implementation will use a more nuanced approach — allowing the full project tree, then using inode-level rules to exclude secrets.

**Requirements:** Linux kernel 5.13+ with Landlock enabled. Falls back to best-effort (env scrub + hooks) on older kernels.

### Windows: Best-Effort

No equivalent lightweight sandbox API. Strategy:
1. Scrub sensitive environment variables from child process
2. Auto-generate ignore files (Layer 1)
3. Install hooks (Layer 2)
4. If WSL2 is detected, offer to run through Linux Landlock path

### Environment Variable Scrubbing (All Platforms)

Regardless of OS sandbox, `secretfence exec` always:
1. Reads `.env` files to discover variable names (not values — just names like `PRIVATE_KEY`)
2. Matches against deny patterns (e.g., `*_SECRET`, `*_KEY`, `MNEMONIC`)
3. Launches the child process with those env vars removed from its environment

### Profiles

Built-in profiles provide curated deny lists:

```toml
# profiles/web3.toml
[profile]
name = "web3"
description = "Foundry, Hardhat, and blockchain development"

deny_paths = [
    ".env", ".env.*", "!.env.example",
    "foundry.toml",
    "hardhat.config.*",
    ".secret", "mnemonic.txt",
    "*.pem", "*.key",
    "deployments/**/secrets.*",
]

deny_env_patterns = [
    "PRIVATE_KEY", "MNEMONIC", "SEED_PHRASE",
    "DEPLOYER_*", "ETHERSCAN_*_KEY",
    "ALCHEMY_*", "INFURA_*",
    "RPC_URL", "*_RPC_URL",
]

# profiles/generic.toml
[profile]
name = "generic"
description = "Common secret patterns across all ecosystems"

deny_paths = [
    ".env", ".env.*", "!.env.example", "!.env.sample",
    "*.pem", "*.key", "*.p12",
    "credentials.*", "secrets.*",
    "serviceAccountKey.json",
    ".npmrc", ".pypirc",
    "terraform.tfvars", "*.auto.tfvars",
]

deny_env_patterns = [
    "*_SECRET", "*_KEY", "*_TOKEN", "*_PASSWORD",
    "AWS_*", "AZURE_*", "GCP_*",
    "DATABASE_URL", "REDIS_URL",
]
```

## Configuration

`.secretfencerc` in project root:

```toml
# Which profile to use by default
profile = "web3"

# Additional path rules (merged with profile + builtins)
[rules]
extra_deny_paths = ["my-custom-secrets.yaml"]
extra_deny_env = ["MY_APP_MASTER_KEY"]

# Override: files that should NOT be flagged
[rules.allow]
paths = [".env.example", "test/fixtures/.env.test"]

# Custom content rules
[[rules.custom]]
id = "internal-api-key"
description = "Internal API key format"
regex = "INTERNAL_[A-Z]+_KEY=[A-Za-z0-9]{32}"
```

## Phased Release Plan

| Phase | Scope | Target |
|-------|-------|--------|
| 0.1.0 | `scan` + `scan --fix` (Layer 1) — detect secrets, generate ignore files | Week 1 |
| 0.2.0 | `hook install` + `hook check` (Layer 2) — Claude Code + Cursor support | Week 2-3 |
| 0.3.0 | `exec` (Layer 3) — macOS sandbox-exec + Linux Landlock | Week 4-5 |
| 0.4.0 | Windows best-effort, additional AI tool support, profiles | Week 6 |
| 1.0.0 | Stable release, docs, homebrew formula | Week 7-8 |

## Verification Plan

### Testing Strategy

**Unit tests:**
- Rule engine: regex matching, entropy calculation, allowlists
- Path detection: glob matching against fixture directories
- Generators: correct output format per tool
- Hook scanner: payload parsing, secret detection, exit codes
- Config loading: `.secretfencerc` parsing, profile merging

**Integration tests:**
- `scan`: run against a fixture project with known secrets, verify all detected
- `scan --fix`: verify correct ignore files generated for each tool
- `hook check`: pipe mock payloads, verify correct block/allow decisions
- `exec`: verify sandboxed process cannot read denied files (macOS + Linux)

**Manual verification:**
- Install hooks in Claude Code, try to read `.env` → should be blocked
- Run `secretfence exec -- claude`, try to `cat .env` → should get EPERM
- Run `secretfence scan` on real projects (cygent, foundry-starter, etc.) → verify no false negatives on known secrets

### Performance targets
- `secretfence scan` on a 10k-file project: <2 seconds
- `secretfence hook check` per invocation: <50ms
- `secretfence exec` startup overhead: <100ms
