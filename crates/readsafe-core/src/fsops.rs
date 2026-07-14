//! File access with the security posture required by the contract:
//! symlinks refused unless explicitly allowed, atomic replacement through a
//! same-directory temp file with restrictive permissions, original
//! permissions preserved, temp files removed on failure, and no OS error
//! strings (which are safe but unstable) leaking into machine output.

use crate::error::{ErrorCode, SafeError};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

fn check_symlink(path: &Path, allow_symlink: bool) -> Result<(), SafeError> {
    if allow_symlink {
        return Ok(());
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(SafeError::new(
                ErrorCode::SymlinkRefused,
                "path is a symbolic link; pass --allow-symlink to follow it",
            )
            .with_path(path.display().to_string()));
        }
    }
    Ok(())
}

/// Read a file as UTF-8 text.
pub fn read_text(path: &Path, allow_symlink: bool) -> Result<String, SafeError> {
    check_symlink(path, allow_symlink)?;
    let display = path.display().to_string();
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    if !allow_symlink {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        const O_NOFOLLOW_FLAG: i32 = 0o400000;
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        const O_NOFOLLOW_FLAG: i32 = 0x00000100;
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        options.custom_flags(O_NOFOLLOW_FLAG);
    }
    let mut file = options.open(path).map_err(|e| {
        let (code, reason) = match e.kind() {
            std::io::ErrorKind::NotFound => (ErrorCode::FileNotFound, "file not found"),
            std::io::ErrorKind::PermissionDenied => (ErrorCode::FileIo, "permission denied"),
            _ => (ErrorCode::FileIo, "file could not be read"),
        };
        SafeError::new(code, reason).with_path(display.clone())
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| {
        SafeError::new(ErrorCode::FileIo, "file could not be read").with_path(display.clone())
    })?;
    String::from_utf8(bytes).map_err(|_| {
        SafeError::new(ErrorCode::FileNotUtf8, "file is not valid UTF-8").with_path(display)
    })
}

/// Atomically replace `path` with `content`.
pub fn atomic_write(path: &Path, content: &str, allow_symlink: bool) -> Result<(), SafeError> {
    check_symlink(path, allow_symlink)?;
    let display = path.display().to_string();
    let io_err =
        |reason: &'static str| SafeError::new(ErrorCode::FileIo, reason).with_path(display.clone());

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let original_perms = fs::metadata(path).ok().map(|m| m.permissions());

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io_err("path has no usable file name"))?;
    let tmp_path = parent.join(format!(
        ".{}.readsafe-tmp-{}",
        file_name,
        std::process::id()
    ));

    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut tmp = options
            .open(&tmp_path)
            .map_err(|_| io_err("could not create temporary file"))?;
        tmp.write_all(content.as_bytes())
            .map_err(|_| io_err("could not write temporary file"))?;
        tmp.sync_all()
            .map_err(|_| io_err("could not flush temporary file"))?;
        drop(tmp);

        if let Some(perms) = original_perms {
            fs::set_permissions(&tmp_path, perms)
                .map_err(|_| io_err("could not preserve file permissions"))?;
        }

        #[cfg(windows)]
        if path.exists() {
            fs::remove_file(path).map_err(|_| io_err("could not replace file"))?;
        }
        fs::rename(&tmp_path, path).map_err(|_| io_err("could not replace file atomically"))
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("readsafe-core-test-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn atomic_write_replaces_and_cleans_up() {
        let dir = temp_dir("atomic");
        let target = dir.join(".env");
        fs::write(&target, "A=1\n").unwrap();
        atomic_write(&target, "A=2\n", false).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "A=2\n");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("readsafe-tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp file left behind");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let target = dir.join(".env");
        fs::write(&target, "A=1\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        atomic_write(&target, "A=2\n", false).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_refused_by_default() {
        let dir = temp_dir("symlink");
        let real = dir.join("real.env");
        fs::write(&real, "A=1\n").unwrap();
        let link = dir.join("link.env");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = read_text(&link, false).unwrap_err();
        assert_eq!(err.code, ErrorCode::SymlinkRefused);
        assert!(read_text(&link, true).is_ok());
        let err = atomic_write(&link, "A=2\n", false).unwrap_err();
        assert_eq!(err.code, ErrorCode::SymlinkRefused);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_utf8_is_a_clean_error() {
        let dir = temp_dir("utf8");
        let target = dir.join("bad.env");
        fs::write(&target, [0x41, 0x3d, 0xff, 0xfe, 0x0a]).unwrap();
        let err = read_text(&target, false).unwrap_err();
        assert_eq!(err.code, ErrorCode::FileNotUtf8);
        let _ = fs::remove_dir_all(&dir);
    }
}
