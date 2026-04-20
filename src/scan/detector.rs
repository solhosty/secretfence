use std::fs;
use std::path::Path;

use anyhow::Result;
use ignore::WalkBuilder;

use crate::rules::{RuleEngine, SecretMatch};

const MAX_FILE_SIZE: u64 = 1_048_576; // 1MB

pub fn scan_directory(path: &Path, engine: &RuleEngine) -> Result<Vec<SecretMatch>> {
    let mut matches = Vec::new();

    let walker = WalkBuilder::new(path)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .build();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let entry_path = entry.path();

        // Skip directories
        if entry_path.is_dir() {
            continue;
        }

        // Get path relative to scan root
        let rel_path = entry_path
            .strip_prefix(path)
            .unwrap_or(entry_path);

        // Check path rules
        if let Some(path_match) = engine.check_path(rel_path) {
            matches.push(SecretMatch::Path {
                file_path: rel_path.display().to_string(),
                rule_id: path_match.rule_id,
                description: path_match.description,
            });
        }

        // Check content rules (only for small enough files)
        let metadata = match fs::metadata(entry_path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.len() > MAX_FILE_SIZE {
            continue;
        }

        // Skip binary files
        if is_likely_binary(entry_path) {
            continue;
        }

        let content = match fs::read_to_string(entry_path) {
            Ok(c) => c,
            Err(_) => continue, // Skip files we can't read as UTF-8
        };

        for content_match in engine.check_content(&content) {
            matches.push(SecretMatch::Content {
                file_path: rel_path.display().to_string(),
                rule_id: content_match.rule_id,
                description: content_match.description,
                line_number: content_match.line_number,
            });
        }
    }

    Ok(matches)
}

fn is_likely_binary(path: &Path) -> bool {
    let binary_extensions = [
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "woff", "woff2",
        "ttf", "eot", "otf", "mp3", "mp4", "avi", "mov", "zip", "tar",
        "gz", "bz2", "xz", "7z", "rar", "pdf", "doc", "docx", "xls",
        "xlsx", "ppt", "pptx", "exe", "dll", "so", "dylib", "o", "a",
        "class", "jar", "pyc", "pyo", "wasm", "db", "sqlite", "sqlite3",
    ];

    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| binary_extensions.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}
