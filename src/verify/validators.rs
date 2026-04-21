use std::fs;
use std::path::Path;
use std::time::Duration;

use colored::Colorize;
use regex::Regex;

use crate::rules::SecretMatch;

#[derive(Debug)]
pub enum VerifyStatus {
    Active,
    Inactive,
    NotVerifiable,
    Error(String),
}

#[derive(Debug)]
pub struct VerifyResult {
    pub file_path: String,
    pub rule_id: String,
    pub description: String,
    pub status: VerifyStatus,
    pub secret_preview: String,
}

pub fn validate_secrets(matches: &[SecretMatch], project_dir: &Path) -> Vec<VerifyResult> {
    println!(
        "\n  {} Verifying detected secrets...\n",
        "secretfence".cyan().bold()
    );

    let mut results = Vec::new();

    // Group content matches by file to avoid re-reading
    let content_matches: Vec<&SecretMatch> = matches
        .iter()
        .filter(|m| matches!(m, SecretMatch::Content { .. }))
        .collect();

    for secret in &content_matches {
        let file_path = secret.file_path();
        let rule_id = secret.rule_id();
        let abs_path = project_dir.join(file_path);

        let content = match fs::read_to_string(&abs_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let line_num = match secret.line_number() {
            Some(n) => n,
            None => continue,
        };

        let line = match content.lines().nth(line_num - 1) {
            Some(l) => l,
            None => continue,
        };

        let result = match rule_id {
            "aws-access-key-id" => verify_aws_key(line, file_path, rule_id),
            "github-token" | "github-oauth" | "github-fine-grained" => {
                verify_github_token(line, file_path, rule_id)
            }
            "slack-token" => verify_slack_token(line, file_path, rule_id),
            "stripe-secret-key" => verify_stripe_key(line, file_path, rule_id),
            "openai-api-key" => verify_openai_key(line, file_path, rule_id),
            "anthropic-api-key" => verify_anthropic_key(line, file_path, rule_id),
            "npm-token" => verify_npm_token(line, file_path, rule_id),
            "sendgrid-api-key" => verify_sendgrid_key(line, file_path, rule_id),
            _ => VerifyResult {
                file_path: file_path.to_string(),
                rule_id: rule_id.to_string(),
                description: secret.description().to_string(),
                status: VerifyStatus::NotVerifiable,
                secret_preview: redact_line(line),
            },
        };

        results.push(result);
    }

    print_verify_report(&results);
    results
}

fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .new_agent()
}

fn extract_value(line: &str, pattern: &str) -> Option<String> {
    let re = Regex::new(pattern).ok()?;
    re.find(line).map(|m| m.as_str().to_string())
}

fn redact_line(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.len() <= 12 {
        return "***".to_string();
    }
    format!("{}...{}", &trimmed[..6], &trimmed[trimmed.len() - 4..])
}

fn verify_aws_key(line: &str, file_path: &str, rule_id: &str) -> VerifyResult {
    let key_id = extract_value(
        line,
        r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    );

    match key_id {
        Some(key) => {
            // AWS key validation requires both access key ID and secret key.
            // We can only confirm the format is valid here.
            VerifyResult {
                file_path: file_path.to_string(),
                rule_id: rule_id.to_string(),
                description: "AWS Access Key ID (format valid, needs secret key to verify)".to_string(),
                status: VerifyStatus::NotVerifiable,
                secret_preview: format!("{}...{}", &key[..4], &key[key.len() - 4..]),
            }
        }
        None => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "AWS Access Key ID".to_string(),
            status: VerifyStatus::NotVerifiable,
            secret_preview: redact_line(line),
        },
    }
}

fn verify_github_token(line: &str, file_path: &str, rule_id: &str) -> VerifyResult {
    let token = extract_value(line, r"gh[pousr]_[A-Za-z0-9_]{36,255}")
        .or_else(|| extract_value(line, r"gho_[A-Za-z0-9]{36,255}"))
        .or_else(|| extract_value(line, r"github_pat_[A-Za-z0-9_]{22,255}"));

    let token = match token {
        Some(t) => t,
        None => {
            return VerifyResult {
                file_path: file_path.to_string(),
                rule_id: rule_id.to_string(),
                description: "GitHub Token".to_string(),
                status: VerifyStatus::NotVerifiable,
                secret_preview: redact_line(line),
            };
        }
    };

    let agent = http_agent();
    match agent
        .get("https://api.github.com/user")
        .header("Authorization", &format!("Bearer {}", token))
        .header("User-Agent", "secretfence")
        .call()
    {
        Ok(response) => {
            let status = response.status();
            if status == 200 {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "GitHub Token — ACTIVE".to_string(),
                    status: VerifyStatus::Active,
                    secret_preview: format!("{}...{}", &token[..6], &token[token.len() - 4..]),
                }
            } else {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "GitHub Token — inactive or revoked".to_string(),
                    status: VerifyStatus::Inactive,
                    secret_preview: format!("{}...{}", &token[..6], &token[token.len() - 4..]),
                }
            }
        }
        Err(ureq::Error::StatusCode(401)) | Err(ureq::Error::StatusCode(403)) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "GitHub Token — inactive or revoked".to_string(),
            status: VerifyStatus::Inactive,
            secret_preview: format!("{}...{}", &token[..6], &token[token.len() - 4..]),
        },
        Err(e) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "GitHub Token".to_string(),
            status: VerifyStatus::Error(e.to_string()),
            secret_preview: format!("{}...{}", &token[..6], &token[token.len() - 4..]),
        },
    }
}

fn verify_slack_token(line: &str, file_path: &str, rule_id: &str) -> VerifyResult {
    let token = match extract_value(line, r"xox[bporas]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*") {
        Some(t) => t,
        None => {
            return VerifyResult {
                file_path: file_path.to_string(),
                rule_id: rule_id.to_string(),
                description: "Slack Token".to_string(),
                status: VerifyStatus::NotVerifiable,
                secret_preview: redact_line(line),
            };
        }
    };

    let agent = http_agent();
    match agent
        .post("https://slack.com/api/auth.test")
        .header("Authorization", &format!("Bearer {}", token))
        .send(&[])
    {
        Ok(response) => {
            let body = response.into_body().read_to_string().unwrap_or_default();
            if body.contains("\"ok\":true") || body.contains("\"ok\": true") {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "Slack Token — ACTIVE".to_string(),
                    status: VerifyStatus::Active,
                    secret_preview: format!("{}...{}", &token[..6], &token[token.len() - 4..]),
                }
            } else {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "Slack Token — inactive or revoked".to_string(),
                    status: VerifyStatus::Inactive,
                    secret_preview: format!("{}...{}", &token[..6], &token[token.len() - 4..]),
                }
            }
        }
        Err(e) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "Slack Token".to_string(),
            status: VerifyStatus::Error(e.to_string()),
            secret_preview: format!("{}...{}", &token[..6], &token[token.len() - 4..]),
        },
    }
}

fn verify_stripe_key(line: &str, file_path: &str, rule_id: &str) -> VerifyResult {
    let key = match extract_value(line, r"sk_live_[A-Za-z0-9]{24,}") {
        Some(k) => k,
        None => {
            return VerifyResult {
                file_path: file_path.to_string(),
                rule_id: rule_id.to_string(),
                description: "Stripe Secret Key".to_string(),
                status: VerifyStatus::NotVerifiable,
                secret_preview: redact_line(line),
            };
        }
    };

    let agent = http_agent();
    match agent
        .get("https://api.stripe.com/v1/charges?limit=1")
        .header("Authorization", &format!("Bearer {}", key))
        .call()
    {
        Ok(response) => {
            let status = response.status();
            if status == 200 {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "Stripe Key — ACTIVE".to_string(),
                    status: VerifyStatus::Active,
                    secret_preview: format!("{}...{}", &key[..10], &key[key.len() - 4..]),
                }
            } else {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "Stripe Key — inactive".to_string(),
                    status: VerifyStatus::Inactive,
                    secret_preview: format!("{}...{}", &key[..10], &key[key.len() - 4..]),
                }
            }
        }
        Err(ureq::Error::StatusCode(401)) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "Stripe Key — inactive".to_string(),
            status: VerifyStatus::Inactive,
            secret_preview: format!("{}...{}", &key[..10], &key[key.len() - 4..]),
        },
        Err(e) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "Stripe Secret Key".to_string(),
            status: VerifyStatus::Error(e.to_string()),
            secret_preview: format!("{}...{}", &key[..10], &key[key.len() - 4..]),
        },
    }
}

fn verify_openai_key(line: &str, file_path: &str, rule_id: &str) -> VerifyResult {
    let key = match extract_value(line, r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}") {
        Some(k) => k,
        None => {
            return VerifyResult {
                file_path: file_path.to_string(),
                rule_id: rule_id.to_string(),
                description: "OpenAI API Key".to_string(),
                status: VerifyStatus::NotVerifiable,
                secret_preview: redact_line(line),
            };
        }
    };

    let agent = http_agent();
    match agent
        .get("https://api.openai.com/v1/models")
        .header("Authorization", &format!("Bearer {}", key))
        .call()
    {
        Ok(response) => {
            if response.status() == 200 {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "OpenAI Key — ACTIVE".to_string(),
                    status: VerifyStatus::Active,
                    secret_preview: format!("sk-{}...", &key[3..9]),
                }
            } else {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "OpenAI Key — inactive".to_string(),
                    status: VerifyStatus::Inactive,
                    secret_preview: format!("sk-{}...", &key[3..9]),
                }
            }
        }
        Err(ureq::Error::StatusCode(401)) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "OpenAI Key — inactive".to_string(),
            status: VerifyStatus::Inactive,
            secret_preview: format!("sk-{}...", &key[3..9]),
        },
        Err(e) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "OpenAI API Key".to_string(),
            status: VerifyStatus::Error(e.to_string()),
            secret_preview: format!("sk-{}...", &key[3..9]),
        },
    }
}

fn verify_anthropic_key(line: &str, file_path: &str, rule_id: &str) -> VerifyResult {
    let key = match extract_value(line, r"sk-ant-[A-Za-z0-9_-]{90,}") {
        Some(k) => k,
        None => {
            return VerifyResult {
                file_path: file_path.to_string(),
                rule_id: rule_id.to_string(),
                description: "Anthropic API Key".to_string(),
                status: VerifyStatus::NotVerifiable,
                secret_preview: redact_line(line),
            };
        }
    };

    let agent = http_agent();
    match agent
        .get("https://api.anthropic.com/v1/models")
        .header("x-api-key", &key)
        .header("anthropic-version", "2023-06-01")
        .call()
    {
        Ok(response) => {
            if response.status() == 200 {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "Anthropic Key — ACTIVE".to_string(),
                    status: VerifyStatus::Active,
                    secret_preview: format!("sk-ant-{}...", &key[7..13]),
                }
            } else {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "Anthropic Key — inactive".to_string(),
                    status: VerifyStatus::Inactive,
                    secret_preview: format!("sk-ant-{}...", &key[7..13]),
                }
            }
        }
        Err(ureq::Error::StatusCode(401)) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "Anthropic Key — inactive".to_string(),
            status: VerifyStatus::Inactive,
            secret_preview: format!("sk-ant-{}...", &key[7..13]),
        },
        Err(e) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "Anthropic API Key".to_string(),
            status: VerifyStatus::Error(e.to_string()),
            secret_preview: format!("sk-ant-{}...", &key[7..13]),
        },
    }
}

fn verify_npm_token(line: &str, file_path: &str, rule_id: &str) -> VerifyResult {
    let token = match extract_value(line, r"npm_[A-Za-z0-9]{36}") {
        Some(t) => t,
        None => {
            return VerifyResult {
                file_path: file_path.to_string(),
                rule_id: rule_id.to_string(),
                description: "npm Token".to_string(),
                status: VerifyStatus::NotVerifiable,
                secret_preview: redact_line(line),
            };
        }
    };

    let agent = http_agent();
    match agent
        .get("https://registry.npmjs.org/-/whoami")
        .header("Authorization", &format!("Bearer {}", token))
        .call()
    {
        Ok(response) => {
            if response.status() == 200 {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "npm Token — ACTIVE".to_string(),
                    status: VerifyStatus::Active,
                    secret_preview: format!("npm_{}...", &token[4..10]),
                }
            } else {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "npm Token — inactive".to_string(),
                    status: VerifyStatus::Inactive,
                    secret_preview: format!("npm_{}...", &token[4..10]),
                }
            }
        }
        Err(ureq::Error::StatusCode(401)) | Err(ureq::Error::StatusCode(403)) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "npm Token — inactive".to_string(),
            status: VerifyStatus::Inactive,
            secret_preview: format!("npm_{}...", &token[4..10]),
        },
        Err(e) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "npm Token".to_string(),
            status: VerifyStatus::Error(e.to_string()),
            secret_preview: format!("npm_{}...", &token[4..10]),
        },
    }
}

fn verify_sendgrid_key(line: &str, file_path: &str, rule_id: &str) -> VerifyResult {
    let key = match extract_value(line, r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}") {
        Some(k) => k,
        None => {
            return VerifyResult {
                file_path: file_path.to_string(),
                rule_id: rule_id.to_string(),
                description: "SendGrid API Key".to_string(),
                status: VerifyStatus::NotVerifiable,
                secret_preview: redact_line(line),
            };
        }
    };

    let agent = http_agent();
    match agent
        .get("https://api.sendgrid.com/v3/scopes")
        .header("Authorization", &format!("Bearer {}", key))
        .call()
    {
        Ok(response) => {
            if response.status() == 200 {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "SendGrid Key — ACTIVE".to_string(),
                    status: VerifyStatus::Active,
                    secret_preview: format!("SG.{}...", &key[3..9]),
                }
            } else {
                VerifyResult {
                    file_path: file_path.to_string(),
                    rule_id: rule_id.to_string(),
                    description: "SendGrid Key — inactive".to_string(),
                    status: VerifyStatus::Inactive,
                    secret_preview: format!("SG.{}...", &key[3..9]),
                }
            }
        }
        Err(ureq::Error::StatusCode(401)) | Err(ureq::Error::StatusCode(403)) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "SendGrid Key — inactive".to_string(),
            status: VerifyStatus::Inactive,
            secret_preview: format!("SG.{}...", &key[3..9]),
        },
        Err(e) => VerifyResult {
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            description: "SendGrid API Key".to_string(),
            status: VerifyStatus::Error(e.to_string()),
            secret_preview: format!("SG.{}...", &key[3..9]),
        },
    }
}

fn print_verify_report(results: &[VerifyResult]) {
    let active: Vec<&VerifyResult> = results
        .iter()
        .filter(|r| matches!(r.status, VerifyStatus::Active))
        .collect();
    let inactive: Vec<&VerifyResult> = results
        .iter()
        .filter(|r| matches!(r.status, VerifyStatus::Inactive))
        .collect();
    let not_verifiable: Vec<&VerifyResult> = results
        .iter()
        .filter(|r| matches!(r.status, VerifyStatus::NotVerifiable))
        .collect();
    let errors: Vec<&VerifyResult> = results
        .iter()
        .filter(|r| matches!(r.status, VerifyStatus::Error(_)))
        .collect();

    if !active.is_empty() {
        println!("  {} {}", "ACTIVE SECRETS:".red().bold(), "(confirmed live credentials)".red());
        for r in &active {
            println!(
                "    {} {:<30} {} ({})",
                "LIVE".red().bold(),
                r.file_path.yellow(),
                r.description,
                r.secret_preview.dimmed()
            );
        }
        println!();
    }

    if !inactive.is_empty() {
        println!("  {}", "INACTIVE/REVOKED:".green().bold());
        for r in &inactive {
            println!(
                "    {} {:<30} {}",
                "dead".green(),
                r.file_path,
                r.description.dimmed()
            );
        }
        println!();
    }

    if !not_verifiable.is_empty() {
        println!(
            "  {} ({} secrets cannot be verified via API)",
            "NOT VERIFIABLE:".dimmed(),
            not_verifiable.len()
        );
        println!();
    }

    if !errors.is_empty() {
        println!("  {}", "ERRORS:".yellow().bold());
        for r in &errors {
            if let VerifyStatus::Error(ref e) = r.status {
                println!("    {} {} — {}", r.file_path.yellow(), r.rule_id, e);
            }
        }
        println!();
    }

    println!(
        "  Summary: {} active, {} inactive, {} unverifiable, {} errors\n",
        active.len().to_string().red().bold(),
        inactive.len().to_string().green(),
        not_verifiable.len().to_string().dimmed(),
        errors.len().to_string().yellow()
    );
}
