use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sf",
    about = "secretfence — Fully local secret protection for AI coding tools",
    version,
    after_help = "https://github.com/Cyfrin/secretfence"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan project for secrets and optionally generate ignore files
    Scan {
        /// Auto-generate ignore files for detected AI tools
        #[arg(long)]
        fix: bool,

        /// Only generate for specific tools (comma-separated: claude,cursor,gemini)
        #[arg(long)]
        tools: Option<String>,

        /// Output in JSON format
        #[arg(long)]
        json: bool,

        /// Directory to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,
    },

    /// Manage real-time hooks for AI coding tools
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },

    /// Run a command inside a sandboxed process
    Exec {
        /// Sandbox profile to use (generic, web3, or custom)
        #[arg(long, default_value = "generic")]
        profile: String,

        /// Additional file paths to deny (comma-separated)
        #[arg(long)]
        deny: Option<String>,

        /// Show sandbox config without running
        #[arg(long)]
        dry_run: bool,

        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Initialize a .secretfencerc config file
    Init,

    /// Manage detection rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
}

#[derive(Subcommand)]
pub enum HookAction {
    /// Install hooks for detected AI tools
    Install {
        /// Only install for specific tools (comma-separated)
        #[arg(long)]
        tools: Option<String>,
    },
    /// Remove all secretfence hooks
    Uninstall,
    /// Scan a hook payload from stdin (called by hooks)
    Check {
        /// Payload format (claude, cursor, gemini)
        #[arg(long)]
        format: String,
    },
}

#[derive(Subcommand)]
pub enum RulesAction {
    /// List all active detection rules
    List,
    /// Test if a file would be flagged
    Test {
        /// File path to test
        path: String,
    },
}
