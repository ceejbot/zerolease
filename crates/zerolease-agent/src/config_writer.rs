//! Config file writer: generates credential-bearing config files
//! (`.npmrc`, `pip.conf`, etc.) from manifest templates.
//!
//! Templates use `${SECRET}` as the placeholder for the credential value.
//! Files are written with mode 0600 (owner read/write only).

use std::fs;
use std::path::{Path, PathBuf};

/// Expand `~` to the user's home directory.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

/// Expand `${SECRET}` placeholders in a template with the actual secret.
pub fn expand_template(template: &str, secret: &str) -> String {
    template.replace("${SECRET}", secret)
}

/// Write a config file with the given content, creating parent
/// directories as needed. On Unix, the file is mode 0600.
pub fn write_config(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_expansion() {
        assert_eq!(expand_template("token=${SECRET}", "abc123"), "token=abc123");
        assert_eq!(
            expand_template("prefix ${SECRET} suffix ${SECRET}", "X"),
            "prefix X suffix X"
        );
        assert_eq!(expand_template("no placeholder", "secret"), "no placeholder");
    }

    #[test]
    fn tilde_expansion() {
        let expanded = expand_tilde("~/.npmrc");
        // Should not start with ~ if HOME is set.
        if std::env::var("HOME").is_ok() {
            assert!(
                !expanded.to_str().map(|s| s.starts_with('~')).unwrap_or(true),
                "tilde should be expanded: {expanded:?}"
            );
        }
    }

    #[test]
    fn tilde_expansion_no_tilde() {
        let path = expand_tilde("/etc/config");
        assert_eq!(path, PathBuf::from("/etc/config"));
    }

    #[test]
    fn write_and_read_config() {
        let dir = tempfile::TempDir::new().expect("should create temp dir");
        let path = dir.path().join("subdir").join("test.conf");

        write_config(&path, "secret_content").expect("should write config");

        let content = fs::read_to_string(&path).expect("should read config");
        assert_eq!(content, "secret_content");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&path).expect("should stat").permissions();
            assert_eq!(perms.mode() & 0o777, 0o600, "config should be mode 0600");
        }
    }
}
