mod claude;
mod cursor;
mod gemini;
mod llmignore;

use std::path::Path;

use anyhow::Result;
use colored::Colorize;

pub trait IgnoreGenerator {
    fn tool_name(&self) -> &str;
    fn is_installed(&self, project_dir: &Path) -> bool;
    fn generate(&self, patterns: &[String], project_dir: &Path) -> Result<GenerateResult>;
}

pub struct GenerateResult {
    pub tool_name: String,
    pub config_path: String,
    pub patterns_added: usize,
}

pub fn all_generators() -> Vec<Box<dyn IgnoreGenerator>> {
    vec![
        Box::new(claude::ClaudeGenerator),
        Box::new(cursor::CursorGenerator),
        Box::new(gemini::GeminiGenerator),
        Box::new(llmignore::LlmignoreGenerator),
    ]
}

pub fn generate_ignore_files(
    patterns: &[String],
    project_dir: &Path,
    tool_filter: Option<&str>,
) -> Result<()> {
    let generators = all_generators();
    let filter_tools: Option<Vec<&str>> = tool_filter.map(|f| f.split(',').collect());
    let mut any_generated = false;

    println!("\n  Generated ignore rules for:");

    for gen in &generators {
        if let Some(ref filter) = filter_tools {
            if !filter.iter().any(|t| t.eq_ignore_ascii_case(gen.tool_name())) {
                continue;
            }
        }

        match gen.generate(patterns, project_dir) {
            Ok(result) => {
                if result.patterns_added > 0 {
                    println!(
                        "    {:<15} {} ({} patterns added)",
                        gen.tool_name().cyan(),
                        result.config_path.dimmed(),
                        result.patterns_added
                    );
                    any_generated = true;
                }
            }
            Err(e) => {
                eprintln!(
                    "    {:<15} {} {}",
                    gen.tool_name().cyan(),
                    "error:".red(),
                    e
                );
            }
        }
    }

    if !any_generated {
        println!("    No new patterns to add.");
    }

    println!();
    Ok(())
}
