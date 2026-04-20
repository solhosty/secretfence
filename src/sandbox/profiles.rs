use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ProfileFile {
    profile: ProfileDef,
}

#[derive(Debug, Deserialize)]
struct ProfileDef {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    description: String,
    deny_paths: Vec<String>,
    deny_env_patterns: Vec<String>,
}

const GENERIC_PROFILE: &str = include_str!("../../profiles/generic.toml");
const WEB3_PROFILE: &str = include_str!("../../profiles/web3.toml");

pub fn load_profile(name: &str) -> (Vec<String>, Vec<String>) {
    let toml_str = match name {
        "web3" => WEB3_PROFILE,
        "generic" | _ => GENERIC_PROFILE,
    };

    match toml::from_str::<ProfileFile>(toml_str) {
        Ok(file) => (file.profile.deny_paths, file.profile.deny_env_patterns),
        Err(e) => {
            eprintln!("[secretfence] Warning: failed to load profile {}: {}", name, e);
            (Vec::new(), Vec::new())
        }
    }
}
