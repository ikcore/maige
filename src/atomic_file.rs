//! Same-directory replacement: the destination is never truncated in place.
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

pub(crate) fn write(path: &Path, contents: &[u8]) -> io::Result<()> {
    write_with(path, |file| file.write_all(contents))
}

fn write_with(path: &Path, writer: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let permissions = match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_file() || meta.permissions().readonly() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Atomic write requires a writable regular destination file",
                ));
            }
            Some(meta.permissions())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let mut staged = tempfile::Builder::new()
        .prefix(".maige-write-")
        .tempfile_in(parent)?;
    writer(staged.as_file_mut())?;
    if let Some(permissions) = permissions {
        staged.as_file().set_permissions(permissions)?;
    }
    staged.as_file().sync_all()?;
    replace(staged.path(), path)?;
    // A failure here means replacement happened, but durability is uncertain.
    // Rotation retains its journal until all such barriers have succeeded.
    sync_dir(parent)
}

#[cfg(not(windows))]
fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, SetFileAttributesW, FILE_ATTRIBUTE_NORMAL, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH,
    };
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Path contains a NUL",
            ));
        }
        value.push(0);
        Ok(value)
    }
    let source = wide(source)?;
    let destination = wide(destination)?;
    // SAFETY: both buffers are NUL-terminated and remain alive for these calls.
    unsafe {
        // NamedTempFile uses FILE_ATTRIBUTE_TEMPORARY; clear it before persisting.
        if SetFileAttributesW(source.as_ptr(), FILE_ATTRIBUTE_NORMAL) == 0 {
            return Err(io::Error::last_os_error());
        }
        if MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    // Windows replacements use MOVEFILE_WRITE_THROUGH instead of directory fsync.
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_write_failure_preserves_original_and_removes_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("realm");
        fs::write(&path, b"original ciphertext").unwrap();
        let result = write_with(&path, |file| {
            file.write_all(b"partial new ciphertext")?;
            Err(io::Error::other("simulated disk full"))
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original ciphertext");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn original_remains_visible_until_complete_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("realm");
        write(&path, b"old").unwrap();
        write_with(&path, |file| {
            file.write_all(b"new")?;
            assert_eq!(fs::read(&path)?, b"old");
            file.write_all(b" complete")
        })
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new complete");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn replacement_failure_preserves_destination() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("realm");
        // Introduce a destination conflict after staging, at the rename boundary.
        let result = write_with(&path, |file| {
            file.write_all(b"new ciphertext")?;
            fs::create_dir(&path)?;
            fs::write(path.join("existing"), b"keep")
        });
        assert!(result.is_err());
        assert_eq!(fs::read(path.join("existing")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn private_permissions_survive_replacement() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("realm");
        write(&path, b"old").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        write(&path, b"new").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_sharing_violation_preserves_original_file() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("realm");
        write(&path, b"original ciphertext").unwrap();
        let _reader = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .unwrap();
        assert!(write(&path, b"new ciphertext").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original ciphertext");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
