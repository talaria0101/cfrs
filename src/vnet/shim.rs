//! Build, locate and configure the `LD_PRELOAD` shim.
//!
//! The shim is C, not Rust, because it has to interpose libc symbols before
//! the program's own constructors run. Its source is embedded in this crate
//! so a `cfrs` binary can drop it in a writable directory, compile it with
//! the host's `cc`, and use it without shipping a second file.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// The shim source, compiled into the binary.
pub const SHIM_SOURCE: &str = include_str!("../../shim/cfrsnet.c");
/// The shim's file name on a unix host.
pub const SHIM_FILE: &str = "libcfrsnet.so";

/// The Tailscale-socksifying shim source, compiled into the binary.
///
/// Separate from [`SHIM_SOURCE`]: this one rewrites `connect(2)` to an
/// `AF_UNIX` SOCKS5 front door for a tailnet address, and leaves every other
/// socket alone. The abstract-name shim and this one are alternative front
/// ends, not layers, so they are built and preloaded separately.
pub const SOCKS_SHIM_SOURCE: &str = include_str!("../../shim/cfrssocks.c");
/// The socksifying shim's file name on a unix host.
pub const SOCKS_SHIM_FILE: &str = "libcfrssocks.so";

/// Configuration passed to the shim through the environment.
#[derive(Clone, Debug)]
pub struct ShimOptions {
    /// The abstract-name prefix (default `cfrsnet`).
    pub prefix: String,
    /// Log every translation to stderr.
    pub log: bool,
    /// Map `127.0.0.1`/`::1` into the virtual subnet.
    pub map_loopback: bool,
    /// A `hosts`-style table for `getaddrinfo` interception.
    pub hosts: Vec<(String, std::net::IpAddr)>,
    /// Enter the stack's control protocol instead of direct mode. `None`
    /// keeps direct mode: two interposed programs talk over abstract names
    /// with no host process.
    pub control: Option<String>,
    /// Size of the shim's per-fd table, used to size the shim's arrays.
    pub max_fds: usize,
}

impl Default for ShimOptions {
    fn default() -> Self {
        Self {
            prefix: "cfrsnet".into(),
            log: false,
            map_loopback: false,
            hosts: Vec::new(),
            control: None,
            max_fds: 65536,
        }
    }
}

impl ShimOptions {
    /// Build the environment a preloaded program needs.
    pub fn environment(&self, shim_path: &Path) -> Vec<(String, String)> {
        let mut env = vec![(
            "LD_PRELOAD".to_string(),
            match std::env::var("LD_PRELOAD") {
                Ok(existing) if !existing.is_empty() => {
                    format!("{}:{existing}", shim_path.display())
                }
                _ => shim_path.display().to_string(),
            },
        )];
        env.push(("CFRSNET_PREFIX".into(), self.prefix.clone()));
        if self.log {
            env.push(("CFRSNET_LOG".into(), "1".into()));
        }
        if self.map_loopback {
            env.push(("CFRSNET_MAP_LOOPBACK".into(), "1".into()));
        }
        if let Some(control) = &self.control {
            env.push(("CFRSNET_CONTROL".into(), control.clone()));
        }
        if !self.hosts.is_empty() {
            let table = self
                .hosts
                .iter()
                .map(|(name, ip)| format!("{name}={ip}"))
                .collect::<Vec<_>>()
                .join(",");
            env.push(("CFRSNET_HOSTS".into(), table));
        }
        env.push(("CFRSNET_MAX_FDS".into(), self.max_fds.to_string()));
        env
    }
}

/// How the shim was obtained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShimOrigin {
    /// `CFRSNET_SHIM` named it.
    Environment,
    /// A previously compiled copy beside the build tree or binary.
    Cached,
    /// It was compiled during this call.
    Compiled,
    /// The crate's own `target/` directory has one.
    BuildTree,
}

/// A located or compiled shim.
#[derive(Clone, Debug)]
pub struct Shim {
    pub path: PathBuf,
    pub origin: ShimOrigin,
}

/// Names searched, in order, when looking for an existing shim.
pub fn candidate_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(value) = std::env::var("CFRSNET_SHIM") {
        if !value.is_empty() {
            out.push(PathBuf::from(value));
        }
    }
    // Beside the running executable.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join(SHIM_FILE));
            out.push(dir.join("shim").join(SHIM_FILE));
        }
    }
    // The crate's target directory, when running from a checkout.
    out.push(PathBuf::from("target/release").join(SHIM_FILE));
    out.push(PathBuf::from("target/debug").join(SHIM_FILE));
    out.push(PathBuf::from("shim").join(SHIM_FILE));
    out
}

/// Find an existing shim, or `None`.
///
/// Candidates are tried in the order [`candidate_paths`] returns them, so an
/// explicit `CFRSNET_SHIM` wins, then the running binary's own directory, then
/// a checkout's build tree.
pub fn locate() -> Option<Shim> {
    let env_shim = std::env::var("CFRSNET_SHIM")
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    for path in candidate_paths() {
        if path.is_file() {
            let origin = if env_shim.as_deref() == Some(path.as_path()) {
                ShimOrigin::Environment
            } else if path.starts_with("target") {
                ShimOrigin::BuildTree
            } else {
                ShimOrigin::Cached
            };
            return Some(Shim { path, origin });
        }
    }
    None
}

/// Find the shim, compiling it if necessary.
///
/// `directory` is where a compiled copy is written when none exists.
pub fn locate_or_build(directory: &Path) -> Result<Shim> {
    if let Some(shim) = locate() {
        return Ok(shim);
    }
    build(directory)
}

/// Find an existing socksifying shim, or `None`.
pub fn locate_socks() -> Option<Shim> {
    let env_shim = std::env::var("CFRSSOCKS_SHIM")
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let mut candidates = Vec::new();
    if let Some(path) = env_shim.clone() {
        candidates.push(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(SOCKS_SHIM_FILE));
            candidates.push(dir.join("shim").join(SOCKS_SHIM_FILE));
        }
    }
    candidates.push(PathBuf::from("target/release").join(SOCKS_SHIM_FILE));
    candidates.push(PathBuf::from("target/debug").join(SOCKS_SHIM_FILE));
    candidates.push(PathBuf::from("shim").join(SOCKS_SHIM_FILE));
    for path in candidates {
        if path.is_file() {
            let origin = if env_shim.as_deref() == Some(path.as_path()) {
                ShimOrigin::Environment
            } else if path.starts_with("target") {
                ShimOrigin::BuildTree
            } else {
                ShimOrigin::Cached
            };
            return Some(Shim { path, origin });
        }
    }
    None
}

/// Compile the embedded shim source into `directory/libcfrsnet.so`.
pub fn build(directory: &Path) -> Result<Shim> {
    compile_source(SHIM_SOURCE, SHIM_FILE, directory)
}

/// Compile the embedded socksifying shim into `directory/libcfrssocks.so`.
pub fn build_socks(directory: &Path) -> Result<Shim> {
    compile_source(SOCKS_SHIM_SOURCE, SOCKS_SHIM_FILE, directory)
}

pub(crate) fn compile_source(source_text: &str, file_name: &str, directory: &Path) -> Result<Shim> {
    std::fs::create_dir_all(directory)
        .with_context(|| format!("creating shim directory {}", directory.display()))?;
    let source = directory.join(file_name.replace(".so", ".c"));
    // Only rewrite when the content differs, so a rebuild loop is cheap and an
    // editor's mtime is not fought.
    let needs_write = std::fs::read(&source)
        .map(|existing| existing != source_text.as_bytes())
        .unwrap_or(true);
    if needs_write {
        std::fs::write(&source, source_text)
            .with_context(|| format!("writing shim source {}", source.display()))?;
    }
    let output = directory.join(file_name);
    let cc = compiler()?;
    let mut command = Command::new(&cc);
    command
        .arg("-O2")
        .arg("-shared")
        .arg("-fPIC")
        .arg("-o")
        .arg(&output)
        .arg(&source)
        .arg("-ldl")
        .arg("-lpthread");
    let result = command
        .output()
        .with_context(|| format!("running {cc} to build the shim"))?;
    if !result.status.success() {
        bail!(
            "compiling the shim failed ({}):\n{}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        );
    }
    if !output.is_file() {
        bail!("{cc} reported success but {} does not exist", output.display());
    }
    Ok(Shim { path: output, origin: ShimOrigin::Compiled })
}

/// The C compiler to use: `$CC`, else `cc`, else `gcc`/`clang`.
pub fn compiler() -> Result<String> {
    if let Ok(cc) = std::env::var("CC") {
        if !cc.trim().is_empty() {
            return Ok(cc);
        }
    }
    for candidate in ["cc", "gcc", "clang"] {
        if which(candidate).is_some() {
            return Ok(candidate.to_string());
        }
    }
    bail!("no C compiler found (set CC, or install cc/gcc/clang)")
}

/// Search `PATH` for an executable.
pub fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Write the embedded source to `path` without compiling, for auditing or
/// for a user who wants to build it themselves.
pub fn write_source(path: &Path) -> Result<()> {
    std::fs::write(path, SHIM_SOURCE)
        .with_context(|| format!("writing shim source {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_is_built() {
        let options = ShimOptions {
            log: true,
            map_loopback: true,
            hosts: vec![("web".into(), "10.66.0.2".parse().unwrap())],
            ..ShimOptions::default()
        };
        let env: std::collections::HashMap<_, _> =
            options.environment(Path::new("/tmp/libcfrsnet.so")).into_iter().collect();
        assert!(env["LD_PRELOAD"].contains("libcfrsnet.so"));
        assert_eq!(env["CFRSNET_LOG"], "1");
        assert_eq!(env["CFRSNET_MAP_LOOPBACK"], "1");
        assert_eq!(env["CFRSNET_HOSTS"], "web=10.66.0.2");
    }

    #[test]
    fn embedded_source_looks_like_the_shim() {
        assert!(SHIM_SOURCE.contains("cfrsnet"));
        assert!(SHIM_SOURCE.contains("dlsym"));
        assert!(SHIM_SOURCE.contains("AF_UNIX"));
    }

    #[test]
    fn finds_a_compiler() {
        // cc or gcc are present on every host this is developed on.
        assert!(compiler().is_ok());
        assert!(which("sh").is_some() || which("cc").is_some());
    }
}
