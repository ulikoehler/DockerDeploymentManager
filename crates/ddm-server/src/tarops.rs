//! Tar archive helpers for container/volume file transfers.
//!
//! Everything here works on plain files: the agent materializes payloads
//! into a `tempfile::TempDir` so the streaming protocol only ever sees a
//! regular file with a known size.

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Read the first two bytes of `path` without consuming the file.
fn starts_with_gzip(path: &Path) -> Result<bool> {
    use std::io::Seek;
    let mut f = std::fs::File::open(path)?;
    let mut magic = [0u8; 2];
    let n = f.read(&mut magic)?;
    f.seek(std::io::SeekFrom::Start(0))?;
    Ok(n == 2 && magic == [0x1f, 0x8b])
}

/// If `path` holds gzip data, decompress it in place (via a sibling temp
/// file + rename). Plain tar passes through untouched.
pub fn ensure_plain_tar(path: &Path) -> Result<()> {
    if !starts_with_gzip(path)? {
        return Ok(());
    }
    let tmp = path.with_extension("tar.plain");
    {
        let src = std::fs::File::open(path)?;
        let dec = flate2::read::GzDecoder::new(src);
        let mut out = std::fs::File::create(&tmp)?;
        std::io::copy(&mut std::io::BufReader::new(dec), &mut out)?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// gzip-compress `src` into a new file next to it (`src` + ".gz").
pub fn gzip_file(src: &Path) -> Result<PathBuf> {
    let out = src.with_extension("tar.gz");
    let input = std::fs::File::open(src)?;
    let mut enc =
        flate2::write::GzEncoder::new(std::fs::File::create(&out)?, flate2::Compression::default());
    std::io::copy(&mut std::io::BufReader::new(input), &mut enc)?;
    enc.finish()?;
    Ok(out)
}

/// Spool an async byte stream into `out`, failing once `cap` bytes have
/// been written. Returns the number of bytes written.
pub async fn spool_stream<S>(mut stream: S, out: &Path, cap: u64) -> Result<u64>
where
    S: futures::Stream<Item = Result<bytes::Bytes>> + Unpin,
{
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    let mut f = tokio::fs::File::create(out).await?;
    let mut n = 0u64;
    while let Some(chunk) = stream.next().await {
        let b = chunk?;
        n += b.len() as u64;
        if n > cap {
            bail!("archive exceeds the {} byte limit", cap);
        }
        f.write_all(&b).await?;
    }
    f.flush().await?;
    Ok(n)
}

/// Write `data` to `out`, failing once `cap` bytes arrive.
pub async fn spool_reader(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    out: &Path,
    cap: u64,
) -> Result<u64> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut f = tokio::fs::File::create(out).await?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut n = 0u64;
    loop {
        let r = reader.read(&mut buf).await?;
        if r == 0 {
            break;
        }
        n += r as u64;
        if n > cap {
            bail!("upload exceeds the {} byte limit", cap);
        }
        f.write_all(&buf[..r]).await?;
    }
    f.flush().await?;
    Ok(n)
}

/// Decompress a gzipped tar at `src` into a plain tar next to it.
/// Non-gzip input is an error — callers sniff first when ambiguous.
pub fn gunzip_tar(src: &Path, dst: &Path) -> Result<()> {
    let input = std::fs::File::open(src)?;
    let mut dec = flate2::read::GzDecoder::new(input);
    let mut out = std::fs::File::create(dst)?;
    std::io::copy(&mut dec, &mut out)?;
    Ok(())
}

/// Extract the contents of the single regular file in `tar_path` into a
/// new file. Fails unless the archive holds exactly one file entry —
/// directories and metadata entries are tolerated, extra files are not.
pub fn extract_single_file(tar_path: &Path, out: &Path) -> Result<()> {
    let f = std::fs::File::open(tar_path)?;
    let mut ar = tar::Archive::new(f);
    let mut files = 0usize;
    // Entries must be consumed in order — the archive cursor cannot go
    // back, so copy each candidate's data as we iterate rather than
    // holding onto an Entry for later.
    let mut dst: Option<std::fs::File> = None;
    for e in ar.entries()? {
        let mut e = e?;
        if e.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        files += 1;
        if files > 1 {
            bail!("archive contains multiple files — use tar/targz format");
        }
        let mut f = std::fs::File::create(out)?;
        std::io::copy(&mut e, &mut f)?;
        dst = Some(f);
    }
    dst.context("archive contains no regular file")?;
    Ok(())
}

/// Build a tar of a host file or directory into `tar_path`, mirroring
/// docker's archive layout: a file becomes a single `basename` entry, a
/// directory becomes `basename/…` entries. `root_children` (used when the
/// source IS a volume root) archives each top-level child by name instead.
pub fn tar_host_path(src: &Path, tar_path: &Path, root_children: bool) -> Result<()> {
    let f = std::fs::File::create(tar_path)?;
    let mut b = tar::Builder::new(f);
    if src.is_dir() {
        if root_children {
            for child in std::fs::read_dir(src)? {
                let child = child?.path();
                let name = child
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                if child.is_dir() {
                    b.append_dir_all(&name, &child)?;
                } else {
                    b.append_path_with_name(&child, &name)?;
                }
            }
        } else {
            let name = src
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .context("source has no name")?;
            b.append_dir_all(&name, src)?;
        }
    } else {
        let name = src
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .context("source has no name")?;
        b.append_path_with_name(src, &name)?;
    }
    b.finish()?;
    Ok(())
}

/// Pack a single file as a tar with one `entry_name` entry — used to wrap
/// a raw upload so the docker archive API can place it.
pub fn tar_single_file(src: &Path, entry_name: &str, out: &Path) -> Result<()> {
    let f = std::fs::File::create(out)?;
    let mut b = tar::Builder::new(f);
    b.append_path_with_name(src, entry_name)?;
    b.finish()?;
    Ok(())
}

/// Safely extract a tar into `dest_dir`. Rejects absolute paths, `..`
/// escapes, and every non-file/non-directory entry type (links, devices,
/// fifos) — a hostile archive must not write outside `dest_dir`.
/// Returns total bytes written; fails past `cap`.
pub fn extract_tar_safe(tar_path: &Path, dest_dir: &Path, cap: u64) -> Result<u64> {
    let f = std::fs::File::open(tar_path)?;
    let mut ar = tar::Archive::new(f);
    let mut written = 0u64;
    for e in ar.entries()? {
        let mut e = e?;
        let p = e.path()?.into_owned();
        let mut safe = !p.as_os_str().is_empty();
        for c in p.components() {
            match c {
                std::path::Component::Normal(_) | std::path::Component::CurDir => {}
                _ => safe = false,
            }
        }
        if !safe {
            bail!("unsafe path in archive: {}", p.display());
        }
        let ty = e.header().entry_type();
        let out = dest_dir.join(&p);
        match ty {
            tar::EntryType::Directory => {
                std::fs::create_dir_all(&out)?;
            }
            tar::EntryType::Regular => {
                if let Some(parent) = out.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut dst = std::fs::File::create(&out)?;
                let n = std::io::copy(&mut e, &mut dst)?;
                written += n;
                if written > cap {
                    bail!("extracted content exceeds the {} byte limit", cap);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(mode) = e.header().mode() {
                        let _ =
                            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode));
                    }
                }
            }
            _ => bail!(
                "unsupported entry type {:?} in archive: {}",
                ty,
                p.display()
            ),
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(d.path().join("sub/b.txt"), b"world!").unwrap();
        d
    }

    #[test]
    fn tar_roundtrip_and_extract_safe() {
        let src = fixture();
        let out = tempfile::tempdir().unwrap();
        let tar = out.path().join("x.tar");
        tar_host_path(src.path(), &tar, false).unwrap();
        let dest = out.path().join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let n = extract_tar_safe(&tar, &dest, 1 << 20).unwrap();
        assert_eq!(n, 11);
        assert_eq!(
            std::fs::read(dest.join(src.path().file_name().unwrap()).join("a.txt")).unwrap(),
            b"hello"
        );
        assert_eq!(
            std::fs::read(dest.join(src.path().file_name().unwrap()).join("sub/b.txt")).unwrap(),
            b"world!"
        );
    }

    #[test]
    fn gzip_roundtrip() {
        let src = fixture();
        let out = tempfile::tempdir().unwrap();
        let tar = out.path().join("x.tar");
        tar_host_path(src.path(), &tar, false).unwrap();
        let gz = gzip_file(&tar).unwrap();
        assert!(starts_with_gzip(&gz).unwrap());
        let plain = out.path().join("plain.tar");
        gunzip_tar(&gz, &plain).unwrap();
        assert!(!starts_with_gzip(&plain).unwrap());
        assert_eq!(std::fs::read(&tar).unwrap(), std::fs::read(&plain).unwrap());
    }

    #[test]
    fn extract_single_file_rejects_multi() {
        let src = fixture();
        let out = tempfile::tempdir().unwrap();
        let tar = out.path().join("x.tar");
        tar_host_path(src.path(), &tar, false).unwrap();
        let one_out = out.path().join("one.bin");
        assert!(extract_single_file(&tar, &one_out).is_err());
        // a single file packs and unpacks
        let one = src.path().join("a.txt");
        let one_tar = out.path().join("one.tar");
        tar_single_file(&one, "one.txt", &one_tar).unwrap();
        let dst = out.path().join("dst.bin");
        extract_single_file(&one_tar, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"hello");
    }

    /// Emit one raw ustar entry (512-byte header + padded data) —
    /// `tar::Builder` refuses `..` names, so hostile archives need raw bytes.
    fn raw_tar_entry(name: &str, ty: u8, data: &[u8]) -> Vec<u8> {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let mut put = |off: usize, len: usize, val: &str| {
            let s = format!(
                "{:0>width$o}",
                val.parse::<u64>().unwrap_or(0),
                width = len - 1
            );
            h[off..off + len - 1].copy_from_slice(s.as_bytes());
            h[off + len - 1] = b' ';
        };
        put(100, 8, "644"); // mode
        put(108, 8, "0"); // uid
        put(116, 8, "0"); // gid
        put(124, 12, &data.len().to_string()); // size
        put(136, 12, "0"); // mtime
        h[156] = ty; // typeflag
        h[257..262].copy_from_slice(b"ustar");
        // checksum: sum of header with chksum field as spaces
        for b in &mut h[148..156] {
            *b = b' ';
        }
        let sum: u32 = h.iter().map(|b| *b as u32).sum();
        let chk = format!("{:06o}\0 ", sum);
        h[148..156].copy_from_slice(chk.as_bytes());
        let mut out = h.to_vec();
        out.extend_from_slice(data);
        let pad = (512 - (data.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    #[test]
    fn safe_extract_rejects_traversal_and_links() {
        let out = tempfile::tempdir().unwrap();
        let tar_path = out.path().join("evil.tar");
        let mut bytes = raw_tar_entry("../escape.txt", b'0', b"evil");
        bytes.extend(raw_tar_entry("link", b'2', b"target")); // symlink
        bytes.extend(std::iter::repeat_n(0u8, 1024)); // end blocks
        std::fs::write(&tar_path, bytes).unwrap();
        let dest = out.path().join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        assert!(extract_tar_safe(&tar_path, &dest, 1 << 20).is_err());
        assert!(!out.path().join("escape.txt").exists());
    }
}
