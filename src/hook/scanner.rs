use std::io::{self, Read};
use std::path::Path;

use anyhow::Result;

use crate::rules::RuleEngine;

pub fn check_hook_payload(format: &str, engine: &RuleEngine) -> Result<bool> {
    let mut payload = String::new();
    io::stdin().read_to_string(&mut payload)?;

    match format {
        "claude" => check_claude_payload(&payload, engine),
        "cursor" => check_generic_payload(&payload, engine),
        "gemini" => check_generic_payload(&payload, engine),
        _ => {
            eprintln!("[secretfence] Unknown format: {}", format);
            Ok(true) // Allow by default for unknown formats
        }
    }
}

fn check_claude_payload(payload: &str, engine: &RuleEngine) -> Result<bool> {
    let parsed: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();

    // Claude Code hook payload has tool_name and tool_input
    let tool_name = parsed
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let tool_input = parsed
        .get("tool_input")
        .cloned()
        .unwrap_or_default();

    // Check file paths in tool input
    let file_path = tool_input
        .get("file_path")
        .or_else(|| tool_input.get("path"))
        .and_then(|v| v.as_str());

    if let Some(path) = file_path {
        let p = Path::new(path);
        if let Some(m) = engine.check_path(p) {
            eprintln!(
                "[secretfence] BLOCKED: {} access to {}",
                tool_name, path
            );
            eprintln!("  Rule: {} — {}", m.rule_id, m.description);
            return Ok(false);
        }
    }

    // Check command content for Bash tool
    if tool_name == "Bash" {
        if let Some(command) = tool_input.get("command").and_then(|v| v.as_str()) {
            let content_matches = engine.check_content(command);
            if !content_matches.is_empty() {
                eprintln!(
                    "[secretfence] BLOCKED: Shell command contains secrets"
                );
                for m in &content_matches {
                    eprintln!("  Rule: {} — {}", m.rule_id, m.description);
                }
                return Ok(false);
            }

            // Also check if the command tries to read a denied file
            for pattern in engine.denied_patterns() {
                if command.contains(&pattern) {
                    eprintln!(
                        "[secretfence] BLOCKED: Shell command accesses {}",
                        pattern
                    );
                    return Ok(false);
                }
            }
        }
    }

    // Check content in write operations
    if tool_name == "Write" || tool_name == "Edit" {
        if let Some(content) = tool_input
            .get("content")
            .or_else(|| tool_input.get("new_string"))
            .and_then(|v| v.as_str())
        {
            let content_matches = engine.check_content(content);
            if !content_matches.is_empty() {
                eprintln!(
                    "[secretfence] WARNING: Write operation may contain secrets"
                );
                for m in &content_matches {
                    eprintln!("  Rule: {} — {}", m.rule_id, m.description);
                }
                // Warn but don't block writes — the AI might be writing .env.example
            }
        }
    }

    Ok(true) // Allow
}

fn check_generic_payload(payload: &str, engine: &RuleEngine) -> Result<bool> {
    // Generic format: check for file paths and content patterns
    let content_matches = engine.check_content(payload);
    if !content_matches.is_empty() {
        eprintln!("[secretfence] BLOCKED: Payload contains secrets");
        for m in &content_matches {
            eprintln!("  Rule: {} — {}", m.rule_id, m.description);
        }
        return Ok(false);
    }

    Ok(true)
}
