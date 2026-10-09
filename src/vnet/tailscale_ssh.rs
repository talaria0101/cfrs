//! Tailscale SSH on a host with no `/etc/passwd` and no writable `/etc`.
//!
//! `tailscaled --ssh` serves an SSH server from inside its userspace netstack,
//! which is the natural way into a sealed host over the tailnet. It resolves
//! the login on the *local* system, though, and a sandbox that denies writes
//! under `/etc` has no `passwd` or `group` for it to find. The failure is not
//! subtle: the session ends with `No user exists for uid N`.
//!
//! `tailscaled` is a static Go binary, so `LD_PRELOAD` cannot interpose its
//! libc. It does not call libc for this anyway. Its `osuser` package runs two
//! helper programs and reads one file:
//!
//! * `getent passwd [--] <name|uid>` — the user and the login shell
//!   ([`GETENT_SHIM`]).
//! * `id -Gz <name>` — the user's group ids, before it ever falls back to
//!   `/etc/group` ([`ID_SHIM`]).
//! * `/etc/group`, only if `id` failed.
//!
//! So two small scripts first on the daemon's `PATH` are enough. The daemon
//! itself is untouched. A *dynamic* client on the same host (OpenSSH's `ssh`,
//! for example) still calls `getpwuid(3)` and needs [`FAKEPWD_SOURCE`]
//! preloaded; that half is a normal `LD_PRELOAD` shim.
//!
//! A second requirement is easy to miss: `tailscaled` needs a writable
//! `--statedir` to generate and keep its SSH host keys. Without one it logs
//! `unable to get SSH host keys, SSH will appear as disabled for this node`
//! and the node never advertises an SSH endpoint.
//!
//! # Limits
//!
//! * The daemon can only serve a login whose uid it already has. A daemon
//!   running as an unprivileged user cannot `setuid(0)`, so `root@` fails no
//!   matter what the user table says; log in as the daemon's own user.
//! * This shims the *server*. Whether a login is allowed at all is the
//!   tailnet's SSH ACL, which the daemon receives from the coordination
//!   server. A `check`-mode rule still asks for a browser approval.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::vnet::shim;

/// The fake `getent`, with `@PASSWD@`/`@GROUP@` placeholders.
pub const GETENT_SHIM: &str = include_str!("../../shim/tsgetent");
/// The fake `id`, with `@PASSWD@`/`@GID@` placeholders.
pub const ID_SHIM: &str = include_str!("../../shim/tsid");
/// The `getpwuid(3)`/`getpwnam(3)` preload for dynamic clients.
pub const FAKEPWD_SOURCE: &str = include_str!("../../shim/fakepwd.c");
/// The compiled name of [`FAKEPWD_SOURCE`].
pub const FAKEPWD_FILE: &str = "fakepwd.so";

/// One entry in the synthetic user table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

impl LocalUser {
    /// A user with the sandbox's usual home and shell.
    pub fn new(name: impl Into<String>, uid: u32, gid: u32) -> Self {
        Self {
            name: name.into(),
            uid,
            gid,
            home: "/state/home".into(),
            shell: "/bin/sh".into(),
        }
    }

    /// The `passwd(5)` line for this user.
    pub fn passwd_line(&self) -> String {
        format!(
            "{}:x:{}:{}:{}:{}:{}",
            self.name, self.uid, self.gid, self.name, self.home, self.shell
        )
    }

    /// The `group(5)` line for this user's primary group.
    pub fn group_line(&self) -> String {
        format!("{}:x:{}:", self.name, self.gid)
    }
}

/// The uid/gid the current process runs as.
pub fn current_ids() -> (u32, u32) {
    // SAFETY: getuid/getgid take no arguments and cannot fail.
    unsafe { (libc::getuid(), libc::getgid()) }
}

/// The current user, named from `$USER` and otherwise from the uid.
pub fn current_user() -> LocalUser {
    let (uid, gid) = current_ids();
    let name = std::env::var("USER")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("u{uid}"));
    LocalUser::new(name, uid, gid)
}

/// The generated files.
#[derive(Clone, Debug)]
pub struct Shims {
    pub dir: PathBuf,
    pub passwd: PathBuf,
    pub group: PathBuf,
    pub getent: PathBuf,
    pub id: PathBuf,
    pub fakepwd: PathBuf,
}

/// Render a `passwd(5)` file: the users given, plus `root` if it is missing.
pub fn render_passwd(users: &[LocalUser]) -> String {
    let mut out = String::new();
    for user in users {
        out.push_str(&user.passwd_line());
        out.push('\n');
    }
    if !users.iter().any(|u| u.name == "root" || u.uid == 0) {
        out.push_str("root:x:0:0:root:/root:/bin/sh\n");
    }
    out
}

/// Render a `group(5)` file: the users' primary groups, plus `root`.
pub fn render_group(users: &[LocalUser]) -> String {
    let mut out = String::new();
    for user in users {
        out.push_str(&user.group_line());
        out.push('\n');
    }
    if !users.iter().any(|u| u.name == "root" || u.gid == 0) {
        out.push_str("root:x:0:\n");
    }
    out
}

/// Fill the placeholders in [`GETENT_SHIM`].
pub fn render_getent(passwd: &Path, group: &Path) -> String {
    GETENT_SHIM
        .replace("@PASSWD@", &passwd.display().to_string())
        .replace("@GROUP@", &group.display().to_string())
}

/// Fill the placeholders in [`ID_SHIM`].
pub fn render_id(passwd: &Path, fallback_gid: u32) -> String {
    ID_SHIM
        .replace("@PASSWD@", &passwd.display().to_string())
        .replace("@GID@", &fallback_gid.to_string())
}

/// Write the user table, the two scripts, and compile the client preload.
///
/// The scripts are made executable; the table is not (it is read by the
/// daemon, which runs as the same user).
pub fn install(dir: &Path, users: &[LocalUser]) -> Result<Shims> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating shim directory {}", dir.display()))?;

    let passwd = dir.join("passwd");
    let group = dir.join("group");
    let getent = dir.join("getent");
    let id = dir.join("id");
    let fallback_gid = users.first().map_or(0, |u| u.gid);

    std::fs::write(&passwd, render_passwd(users))
        .with_context(|| format!("writing {}", passwd.display()))?;
    std::fs::write(&group, render_group(users))
        .with_context(|| format!("writing {}", group.display()))?;
    write_executable(&getent, &render_getent(&passwd, &group))?;
    write_executable(&id, &render_id(&passwd, fallback_gid))?;

    let compiled = shim::compile_source(FAKEPWD_SOURCE, FAKEPWD_FILE, dir)?;

    Ok(Shims {
        dir: dir.to_path_buf(),
        passwd,
        group,
        getent,
        id,
        fakepwd: compiled.path,
    })
}

fn write_executable(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("chmod 0755 {}", path.display()))?;
    Ok(())
}

/// The environment a dynamic client needs to see the synthetic users.
pub fn client_environment(shims: &Shims) -> Vec<(String, String)> {
    let preload = match std::env::var("LD_PRELOAD") {
        Ok(existing) if !existing.is_empty() => {
            format!("{}:{existing}", shims.fakepwd.display())
        }
        _ => shims.fakepwd.display().to_string(),
    };
    vec![
        ("LD_PRELOAD".into(), preload),
        ("SANDHOME_PASSWD".into(), shims.passwd.display().to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cfrs-ts-shims-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn passwd_and_group_include_root() {
        let user = LocalUser::new("nemo", 966, 965);
        let passwd = render_passwd(&[user.clone()]);
        assert!(passwd.contains("nemo:x:966:965:nemo:/state/home:/bin/sh"));
        assert!(passwd.contains("root:x:0:0:root:/root:/bin/sh"));
        let group = render_group(&[user]);
        assert!(group.contains("nemo:x:965:"));
        assert!(group.contains("root:x:0:"));
    }

    #[test]
    fn getent_answers_name_and_uid() {
        let dir = scratch("getent");
        let shims = install(&dir, &[LocalUser::new("nemo", 966, 965)]).unwrap();

        let by_name = std::process::Command::new(&shims.getent)
            .args(["passwd", "--", "nemo"])
            .output()
            .unwrap();
        assert!(by_name.status.success());
        assert_eq!(
            String::from_utf8_lossy(&by_name.stdout).trim(),
            "nemo:x:966:965:nemo:/state/home:/bin/sh"
        );

        // The probe that decides whether `--` is accepted asks twice.
        let plain = std::process::Command::new(&shims.getent)
            .args(["passwd", "root"])
            .output()
            .unwrap();
        let dashed = std::process::Command::new(&shims.getent)
            .args(["passwd", "--", "root"])
            .output()
            .unwrap();
        assert_eq!(plain.stdout, dashed.stdout);

        let by_uid = std::process::Command::new(&shims.getent)
            .args(["passwd", "966"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&by_uid.stdout).starts_with("nemo:"));

        let missing = std::process::Command::new(&shims.getent)
            .args(["passwd", "nosuch"])
            .output()
            .unwrap();
        assert_eq!(missing.status.code(), Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn id_answers_group_list() {
        let dir = scratch("id");
        let shims = install(&dir, &[LocalUser::new("nemo", 966, 965)]).unwrap();

        let out = std::process::Command::new(&shims.id)
            .args(["-Gz", "nemo"])
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"965\0");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_compiles_the_client_preload() {
        let dir = scratch("fakepwd");
        let shims = install(&dir, &[LocalUser::new("nemo", 966, 965)]).unwrap();
        assert!(
            shims.fakepwd.is_file(),
            "{} was not built",
            shims.fakepwd.display()
        );
        let env = client_environment(&shims);
        assert!(env
            .iter()
            .any(|(k, v)| k == "LD_PRELOAD" && v.ends_with("fakepwd.so")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
