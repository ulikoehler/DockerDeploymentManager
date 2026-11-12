//! Minimal OCI Distribution Spec store backing the `/v2/` endpoints.
//!
//! Layout under `<config dir>/registry/`:
//!   blobs/<algo>/<hex>            content-addressed blob store
//!   manifests/<name>/<reference>  manifest bytes (+ `.ct` content-type)
//!   uploads/<uuid>                in-flight blob uploads
//!   tmp/<uuid>/                   scratch space for `docker load` tars
//!
//! Pushed images are also imported into the local docker daemon via
//! `docker load` (see `assemble_load_tar` + `ExecVerb::ImageLoad`).

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

pub struct Registry {
    root: PathBuf,
}

/// Repo-name validation (docker distribution grammar, simplified):
/// lowercase path components of `[a-z0-9]` joined by runs of
/// `.`, `_`, `__`, `-` or `/`. No `..`, no leading/trailing separators.
pub fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    name.split('/').all(|seg| {
        !seg.is_empty()
            && seg.len() <= 128
            && seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
            && !seg.contains("..")
            && seg
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}

/// `algo:hex` digest — algo lowercase alnum, hex lowercase.
pub fn valid_digest(d: &str) -> bool {
    let Some((algo, hex)) = d.split_once(':') else {
        return false;
    };
    !algo.is_empty()
        && algo.len() <= 16
        && algo
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && hex.len() >= 32
        && hex.len() <= 128
        && hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Manifest reference: a tag (`[\w][\w.-]{0,127}`) or a digest.
pub fn valid_reference(r: &str) -> bool {
    if r.is_empty() || r.len() > 255 {
        return false;
    }
    if valid_digest(r) {
        return true;
    }
    !r.contains('/')
        && !r.contains(':')
        && r.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub fn valid_uuid(u: &str) -> bool {
    uuid::Uuid::parse_str(u).is_ok()
}

impl Registry {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn blob_path(&self, digest: &str) -> PathBuf {
        let (algo, hex) = digest.split_once(':').unwrap_or(("sha256", digest));
        self.root.join("blobs").join(algo).join(hex)
    }

    fn manifest_path(&self, name: &str, reference: &str) -> PathBuf {
        self.root.join("manifests").join(name).join(reference)
    }

    fn manifest_ct_path(&self, name: &str, reference: &str) -> PathBuf {
        let mut p = self.manifest_path(name, reference);
        p.set_extension("ct");
        p
    }

    fn upload_path(&self, uuid: &str) -> PathBuf {
        self.root.join("uploads").join(uuid)
    }

    pub fn has_blob(&self, digest: &str) -> bool {
        self.blob_path(digest).is_file()
    }

    pub fn blob_size(&self, digest: &str) -> u64 {
        std::fs::metadata(self.blob_path(digest))
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Open a blob for streaming (GET/HEAD).
    pub fn open_blob(&self, digest: &str) -> Result<std::fs::File> {
        std::fs::File::open(self.blob_path(digest))
            .with_context(|| format!("blob {digest} not found"))
    }

    /// Store a complete blob in one shot (monolithic upload).
    pub fn store_blob(&self, digest: &str, data: &[u8]) -> Result<()> {
        self.verify_digest(digest, data)?;
        let path = self.blob_path(digest);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Create the upload scratch file; returns its path.
    pub fn begin_upload(&self, uuid: &str) -> Result<PathBuf> {
        let dir = self.root.join("uploads");
        std::fs::create_dir_all(&dir)?;
        let path = self.upload_path(uuid);
        std::fs::File::create(&path)?;
        Ok(path)
    }

    /// Finalize an upload: verify the digest and move it into the blob
    /// store. Returns the blob's byte size.
    pub fn finalize_upload(&self, uuid: &str, digest: &str) -> Result<u64> {
        if !valid_digest(digest) {
            bail!("invalid digest {digest}");
        }
        let up = self.upload_path(uuid);
        let size = std::fs::metadata(&up)
            .with_context(|| format!("unknown upload {uuid}"))?
            .len();
        // Stream-hash so multi-GB layers don't land in memory.
        let mut f = std::fs::File::open(&up)?;
        let mut h = Sha256::new();
        let mut buf = [0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        let actual = format!("sha256:{}", hex::encode(h.finalize()));
        if digest != actual {
            let _ = std::fs::remove_file(&up);
            bail!("digest mismatch: declared {digest}, content is {actual}");
        }
        let dest = self.blob_path(digest);
        if let Some(p) = dest.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::rename(&up, &dest)?;
        Ok(size)
    }

    /// Abort/delete an in-flight upload.
    pub fn abort_upload(&self, uuid: &str) {
        let _ = std::fs::remove_file(self.upload_path(uuid));
    }

    /// Store manifest bytes + content type atomically.
    pub fn store_manifest(
        &self,
        name: &str,
        reference: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> Result<()> {
        let path = self.manifest_path(name, reference);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        std::fs::write(self.manifest_ct_path(name, reference), content_type)?;
        Ok(())
    }

    pub fn get_manifest(&self, name: &str, reference: &str) -> Result<(Vec<u8>, String)> {
        let bytes = std::fs::read(self.manifest_path(name, reference))
            .with_context(|| format!("manifest {name}:{reference} not found"))?;
        let ct = std::fs::read_to_string(self.manifest_ct_path(name, reference))
            .unwrap_or_else(|_| "application/vnd.oci.image.manifest.v1+json".into());
        Ok((bytes, ct))
    }

    /// Tag names under a repo (excludes digest references, which contain ':').
    pub fn list_tags(&self, name: &str) -> Result<Vec<String>> {
        let dir = self.root.join("manifests").join(name);
        let mut tags: Vec<String> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter(|n| !n.contains(':') && !n.ends_with(".tmp") && !n.ends_with(".ct"))
                .collect(),
            Err(_) => Vec::new(),
        };
        tags.sort();
        Ok(tags)
    }

    /// Repo names that have at least one manifest.
    pub fn catalog(&self) -> Result<Vec<String>> {
        let base = self.root.join("manifests");
        let mut repos = Vec::new();
        if !base.is_dir() {
            return Ok(repos);
        }
        let mut stack = vec![base.clone()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir)?.filter_map(|e| e.ok()) {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    !n.contains(':') && !n.ends_with(".ct") && !n.ends_with(".tmp")
                }) && p.parent().is_some_and(|par| par != base)
                {
                    // leaf manifest file → repo = path relative to base
                    if let Ok(rel) = p.parent().unwrap().strip_prefix(&base) {
                        repos.push(rel.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
        }
        repos.sort();
        repos.dedup();
        Ok(repos)
    }

    /// Parse a manifest and return (config digest, layer digests).
    /// Returns None for manifest lists / indexes (no config+layers).
    pub fn manifest_parts(bytes: &[u8]) -> Result<Option<(String, Vec<String>)>> {
        let v: serde_json::Value =
            serde_json::from_slice(bytes).context("manifest is not valid JSON")?;
        let Some(cfg) = v.pointer("/config/digest").and_then(|d| d.as_str()) else {
            return Ok(None); // index / manifest list
        };
        let layers: Vec<String> = v
            .get("layers")
            .and_then(|l| l.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|l| l.get("digest").and_then(|d| d.as_str()))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Some((cfg.to_string(), layers)))
    }

    /// Build a `docker load`-compatible tar for a pushed manifest.
    /// Returns (tar_path, scratch_dir) — caller must clean up scratch_dir
    /// after the load finishes.
    pub fn assemble_load_tar(&self, name: &str, reference: &str) -> Result<(PathBuf, PathBuf)> {
        if !valid_name(name) || !valid_reference(reference) || reference.contains(':') {
            bail!("cannot build load tar for {name}:{reference}");
        }
        let (mbytes, _) = self.get_manifest(name, reference)?;
        let Some((cfg_digest, layer_digests)) = Self::manifest_parts(&mbytes)? else {
            bail!("manifest lists / indexes are stored but not loaded into docker");
        };
        for d in std::iter::once(&cfg_digest).chain(layer_digests.iter()) {
            if !self.has_blob(d) {
                bail!("missing blob {d} for {name}:{reference}");
            }
        }

        let scratch = self.root.join("tmp").join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&scratch)?;
        let result = (|| -> Result<PathBuf> {
            // config blob -> <hex>.json
            let cfg_hex = cfg_digest.rsplit(':').next().unwrap_or(&cfg_digest);
            let cfg_name = format!("{cfg_hex}.json");
            let cfg_path = scratch.join(&cfg_name);
            std::fs::write(&cfg_path, self.read_blob(&cfg_digest)?)?;

            // layers -> layer-N.tar (decompressed if gzipped)
            let mut layer_names = Vec::new();
            for (i, dig) in layer_digests.iter().enumerate() {
                let lname = format!("layer-{i}.tar");
                let lpath = scratch.join(&lname);
                self.write_plain_layer(dig, &lpath)?;
                layer_names.push(lname);
            }

            // manifest.json
            let repo_tag = format!("{name}:{reference}");
            let mj = serde_json::json!([{
                "Config": cfg_name,
                "RepoTags": [repo_tag],
                "Layers": layer_names,
            }]);
            let mj_path = scratch.join("manifest.json");
            std::fs::write(&mj_path, mj.to_string())?;

            // outer tar
            let tar_path = scratch.join("image.tar");
            let out = std::fs::File::create(&tar_path)?;
            let mut b = tar::Builder::new(out);
            b.append_path_with_name(&cfg_path, &cfg_name)?;
            for (i, _) in layer_digests.iter().enumerate() {
                let lname = format!("layer-{i}.tar");
                b.append_path_with_name(scratch.join(&lname), &lname)?;
            }
            b.append_path_with_name(&mj_path, "manifest.json")?;
            b.finish()?;
            Ok(tar_path)
        })();
        match result {
            Ok(p) => Ok((p, scratch)),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&scratch);
                Err(e)
            }
        }
    }

    fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        Ok(std::fs::read(self.blob_path(digest))?)
    }

    /// Write a layer blob as a plain (uncompressed) tar — docker save
    /// format expects plain tars; pass through already-plain content.
    fn write_plain_layer(&self, digest: &str, out: &Path) -> Result<()> {
        let mut src = std::fs::File::open(self.blob_path(digest))?;
        let mut magic = [0u8; 2];
        let n = src.read(&mut magic)?;
        let gzipped = n == 2 && magic == [0x1f, 0x8b];
        use std::io::Seek;
        src.seek(std::io::SeekFrom::Start(0))?;
        let mut dst = std::fs::File::create(out)?;
        if gzipped {
            let mut dec = flate2::read::GzDecoder::new(src);
            std::io::copy(&mut dec, &mut dst)?;
        } else {
            std::io::copy(&mut src, &mut dst)?;
        }
        Ok(())
    }

    /// sha256 of `data`, for verifying direct blob stores.
    fn verify_digest(&self, digest: &str, data: &[u8]) -> Result<()> {
        if !valid_digest(digest) {
            bail!("invalid digest {digest}");
        }
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(data)));
        // Only enforce when the algo is sha256 — other algos are stored
        // as declared (docker always uses sha256 anyway).
        if digest.starts_with("sha256:") && digest != actual {
            bail!("digest mismatch: declared {digest}, content is {actual}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        assert!(valid_name("myimage"));
        assert!(valid_name("library/nginx"));
        assert!(valid_name("foo.bar/baz-qux_1"));
        assert!(!valid_name(""));
        assert!(!valid_name("../etc"));
        assert!(!valid_name("Foo/Bar"));
        assert!(!valid_name("a//b"));
        assert!(!valid_name("-lead"));
        assert!(!valid_name(&"a".repeat(256)));
    }

    #[test]
    fn digest_validation() {
        assert!(valid_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_digest("sha256:xyz"));
        assert!(!valid_digest(
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!valid_digest("nocolon"));
    }

    #[test]
    fn reference_validation() {
        assert!(valid_reference("latest"));
        assert!(valid_reference("v1.2.3-rc.1"));
        assert!(valid_reference(&format!("sha256:{}", "b".repeat(64))));
        assert!(!valid_reference("has/slash"));
        assert!(!valid_reference("has:colon"));
    }

    #[test]
    fn blob_roundtrip_and_digest_check() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::new(dir.path().to_path_buf());
        let data = b"hello blob";
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));
        reg.store_blob(&digest, data).unwrap();
        assert!(reg.has_blob(&digest));
        assert_eq!(reg.blob_size(&digest), data.len() as u64);
        // wrong digest rejected
        let bad = format!("sha256:{}", "0".repeat(64));
        assert!(reg.store_blob(&bad, data).is_err());
    }

    #[test]
    fn upload_finalize_verifies_content() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::new(dir.path().to_path_buf());
        let id = uuid::Uuid::new_v4().to_string();
        reg.begin_upload(&id).unwrap();
        let up = dir.path().join("uploads").join(&id);
        std::fs::write(&up, b"chunk1chunk2").unwrap();
        let data = b"chunk1chunk2";
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));
        let size = reg.finalize_upload(&id, &digest).unwrap();
        assert_eq!(size, data.len() as u64);
        assert!(reg.has_blob(&digest));
        assert!(!reg.root().join("uploads").join(&id).exists());
        // tampered content fails
        let id2 = uuid::Uuid::new_v4().to_string();
        reg.begin_upload(&id2).unwrap();
        std::fs::write(dir.path().join("uploads").join(&id2), b"tampered").unwrap();
        assert!(reg.finalize_upload(&id2, &digest).is_err());
    }

    #[test]
    fn manifest_store_tags_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::new(dir.path().to_path_buf());
        let m = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[]}"#;
        reg.store_manifest(
            "foo/bar",
            "latest",
            m,
            "application/vnd.oci.image.manifest.v1+json",
        )
        .unwrap();
        reg.store_manifest(
            "foo/bar",
            &format!("sha256:{}", "c".repeat(64)),
            m,
            "application/vnd.oci.image.manifest.v1+json",
        )
        .unwrap();
        assert_eq!(reg.list_tags("foo/bar").unwrap(), vec!["latest"]);
        assert_eq!(reg.catalog().unwrap(), vec!["foo/bar"]);
        let (bytes, ct) = reg.get_manifest("foo/bar", "latest").unwrap();
        assert_eq!(bytes, m);
        assert!(ct.contains("oci"));
        let parts = Registry::manifest_parts(m).unwrap().unwrap();
        assert_eq!(parts.0, format!("sha256:{}", "a".repeat(64)));
        assert!(parts.1.is_empty());
        // index has no config -> None
        let idx = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#;
        assert!(Registry::manifest_parts(idx).unwrap().is_none());
    }
}
