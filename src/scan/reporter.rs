use colored::Colorize;

use crate::rules::SecretMatch;

pub fn print_report(matches: &[SecretMatch]) {
    if matches.is_empty() {
        println!("\n  {} No secrets found.\n", "✓".green().bold());
        return;
    }

    let mut path_matches: Vec<&SecretMatch> = Vec::new();
    let mut content_matches: Vec<&SecretMatch> = Vec::new();

    for m in matches {
        match m {
            SecretMatch::Path { .. } => path_matches.push(m),
            SecretMatch::Content { .. } => content_matches.push(m),
        }
    }

    println!();

    if !path_matches.is_empty() {
        println!("  {}", "SECRET FILES:".red().bold());
        println!();
        for m in &path_matches {
            println!(
                "  {:<30} {}",
                m.file_path().yellow(),
                m.description().dimmed()
            );
        }
        println!();
    }

    if !content_matches.is_empty() {
        println!("  {}", "CONTENT MATCHES:".red().bold());
        println!();
        for m in &content_matches {
            let location = if let Some(line) = m.line_number() {
                format!("{}:{}", m.file_path(), line)
            } else {
                m.file_path().to_string()
            };
            println!(
                "  {:<30} {}",
                location.yellow(),
                m.description().dimmed()
            );
        }
        println!();
    }

    let file_count = {
        let mut files: Vec<&str> = matches.iter().map(|m| m.file_path()).collect();
        files.sort();
        files.dedup();
        files.len()
    };

    println!(
        "  Found {} in {} {}.\n",
        format!("{} secrets", matches.len()).red().bold(),
        file_count,
        if file_count == 1 { "file" } else { "files" }
    );

    println!(
        "  Run {} to generate ignore files for your AI tools.\n",
        "sf scan --fix".cyan()
    );
}

pub fn print_json(matches: &[SecretMatch]) {
    let entries: Vec<serde_json::Value> = matches
        .iter()
        .map(|m| {
            let mut obj = serde_json::Map::new();
            obj.insert("file".into(), serde_json::Value::String(m.file_path().to_string()));
            obj.insert("rule_id".into(), serde_json::Value::String(m.rule_id().to_string()));
            obj.insert("description".into(), serde_json::Value::String(m.description().to_string()));
            obj.insert("type".into(), serde_json::Value::String(
                match m {
                    SecretMatch::Path { .. } => "path",
                    SecretMatch::Content { .. } => "content",
                }.to_string()
            ));
            if let Some(line) = m.line_number() {
                obj.insert("line".into(), serde_json::Value::Number(line.into()));
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&entries).unwrap_or_default());
}
