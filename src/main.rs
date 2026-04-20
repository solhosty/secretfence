mod cli;
mod config;
mod hook;
mod rules;
mod sandbox;
mod scan;

use std::path::Path;
use std::process;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;

use cli::{Cli, Commands, HookAction, RulesAction};

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("{} {}", "error:".red().bold(), e);
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Scan {
            fix,
            tools,
            json,
            path,
        } => cmd_scan(&path, fix, tools.as_deref(), json),

        Commands::Hook { action } => match action {
            HookAction::Install { tools } => {
                let dir = std::env::current_dir()?;
                hook::installer::install_hooks(&dir, tools.as_deref())
            }
            HookAction::Uninstall => {
                let dir = std::env::current_dir()?;
                hook::installer::uninstall_hooks(&dir)
            }
            HookAction::Check { format } => cmd_hook_check(&format),
        },

        Commands::Exec {
            profile,
            deny,
            dry_run,
            command,
        } => cmd_exec(&profile, deny.as_deref(), dry_run, &command),

        Commands::Init => {
            let dir = std::env::current_dir()?;
            config::init_config(&dir)
        }

        Commands::Rules { action } => match action {
            RulesAction::List => cmd_rules_list(),
            RulesAction::Test { path } => cmd_rules_test(&path),
        },
    }
}

fn cmd_scan(path: &str, fix: bool, tools: Option<&str>, json: bool) -> Result<()> {
    let project_dir = Path::new(path).canonicalize()?;

    let (content_rules, path_rules) = rules::load_rules()?;
    let engine = rules::RuleEngine::new(content_rules, path_rules)?;

    let matches = scan::detector::scan_directory(&project_dir, &engine)?;

    if json {
        scan::reporter::print_json(&matches);
    } else {
        if !fix {
            println!(
                "\n  {} scanning project...\n",
                "secretfence".cyan().bold()
            );
        }
        scan::reporter::print_report(&matches);
    }

    if fix {
        let patterns = engine.denied_patterns();
        scan::generators::generate_ignore_files(&patterns, &project_dir, tools)?;
    }

    if !matches.is_empty() && !fix && !json {
        process::exit(1);
    }

    Ok(())
}

fn cmd_hook_check(format: &str) -> Result<()> {
    let (content_rules, path_rules) = rules::load_rules()?;
    let engine = rules::RuleEngine::new(content_rules, path_rules)?;

    let allowed = hook::scanner::check_hook_payload(format, &engine)?;

    if allowed {
        process::exit(0);
    } else {
        process::exit(2);
    }
}

fn cmd_exec(profile: &str, deny: Option<&str>, dry_run: bool, command: &[String]) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config = config::load_config(&project_dir);

    let profile_name = config
        .profile
        .as_deref()
        .unwrap_or(profile);

    let (mut deny_paths, mut deny_env) = sandbox::load_profile(profile_name);

    if let Some(ref rules) = config.rules {
        deny_paths.extend(rules.extra_deny_paths.clone());
        deny_env.extend(rules.extra_deny_env.clone());
    }

    if let Some(deny_str) = deny {
        deny_paths.extend(deny_str.split(',').map(String::from));
    }

    let sandbox_config = sandbox::SandboxConfig {
        deny_paths,
        deny_env,
        command: command.to_vec(),
    };

    sandbox::exec_sandboxed(&sandbox_config, &project_dir, dry_run)
}

fn cmd_rules_list() -> Result<()> {
    let (content_rules, path_rules) = rules::load_rules()?;

    println!("\n  {} Active rules:\n", "secretfence".cyan().bold());

    println!("  {}", "PATH RULES:".bold());
    for rule in &path_rules {
        println!(
            "    {:<25} {}",
            rule.id.yellow(),
            rule.description
        );
        for pattern in &rule.patterns {
            println!("      {}", pattern.dimmed());
        }
    }

    println!("\n  {}", "CONTENT RULES:".bold());
    for rule in &content_rules {
        println!(
            "    {:<30} {}",
            rule.id.yellow(),
            rule.description
        );
    }

    println!(
        "\n  {} path rules, {} content rules\n",
        path_rules.len().to_string().green(),
        content_rules.len().to_string().green()
    );

    Ok(())
}

fn cmd_rules_test(path: &str) -> Result<()> {
    let (content_rules, path_rules) = rules::load_rules()?;
    let engine = rules::RuleEngine::new(content_rules, path_rules)?;

    let test_path = Path::new(path);

    if let Some(m) = engine.check_path(test_path) {
        println!(
            "\n  {} {} matched by path rule: {} — {}\n",
            "FLAGGED".red().bold(),
            path.yellow(),
            m.rule_id,
            m.description
        );
    } else {
        println!(
            "\n  {} {} not matched by any path rule",
            "CLEAN".green().bold(),
            path
        );
    }

    if test_path.exists() {
        if let Ok(content) = std::fs::read_to_string(test_path) {
            let matches = engine.check_content(&content);
            if !matches.is_empty() {
                println!("  Content matches:");
                for m in &matches {
                    println!(
                        "    line {}: {} — {}",
                        m.line_number,
                        m.rule_id.yellow(),
                        m.description
                    );
                }
            } else {
                println!("  No content matches found.");
            }
        }
    }

    println!();
    Ok(())
}
