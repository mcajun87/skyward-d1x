//! The files a part of a backup is kept in: what the part holds, compressed
//! or not, cut into files of a size every filesystem a backup may go to
//! takes, with a digest of what it holds to check it by.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Result, anyhow, ensure};
use lz4_flex::frame::{BlockSize, FrameDecoder, FrameEncoder, FrameInfo};
use md5::Md5;
use scrypt::{Params, scrypt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use skyward_files::Ownership;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

/// The most one file holds: FAT, which USB drives often hold, takes no file
/// of 4 GiB or more.
pub const FILE_BYTES: u64 = 1 << 30;

/// A part as its files keep it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    /// The files, in order, in the backup's folder.
    pub files: Vec<String>,
    /// The bytes the part holds, and the bytes its files take.
    pub size: u64,
    pub stored: u64,
    pub compressed: bool,
    /// The SHA-256 of what the part holds, in hex.
    pub sha256: String,
    /// The MD5 of what the part holds, in hex. A backup written before
    /// MD5 was kept has none.
    #[serde(default)]
    pub md5: String,
    /// How the files are encrypted, when they are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Encryption>,
}

/// How one part's files are encrypted: a passphrase stretched with scrypt,
/// then AES-256-GCM over chunks of the stream. The salt and the nonce
/// prefix are written here, in the manifest, so a restore needs only the
/// passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encryption {
    /// The cipher, `aes-256-gcm`.
    pub cipher: String,
    /// The key derivation, `scrypt`.
    pub kdf: String,
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    /// The salt scrypt takes, in hex.
    pub salt: String,
    /// The first 8 bytes of each nonce, in hex; the rest counts the chunks.
    pub nonce: String,
    /// The bytes of plaintext in each chunk.
    pub chunk: u64,
}

impl Encryption {
    /// What every backup this recovery encrypts is kept by.
    pub const CIPHER: &'static str = "aes-256-gcm";
    pub const KDF: &'static str = "scrypt";
    pub const CHUNK: u64 = 4 << 20;

    /// A fresh salt and nonce, for one part.
    pub fn new() -> Result<Encryption> {
        let salt: [u8; 16] = random_bytes().context("read a salt")?;
        let nonce: [u8; 8] = random_bytes().context("read a nonce")?;
        Ok(Encryption {
            cipher: Self::CIPHER.into(),
            kdf: Self::KDF.into(),
            log_n: 15,
            r: 8,
            p: 1,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            chunk: Self::CHUNK,
        })
    }

    /// The key `password` stretches to, as the manifest records how.
    pub fn derive(&self, password: &str) -> Result<[u8; 32]> {
        ensure!(
            self.cipher == Self::CIPHER,
            "unsupported backup cipher {}",
            self.cipher
        );
        ensure!(
            self.kdf == Self::KDF,
            "unsupported backup key derivation {}",
            self.kdf
        );
        ensure!(
            (12..=16).contains(&self.log_n),
            "backup scrypt log_n {}",
            self.log_n
        );
        ensure!((1..=16).contains(&self.r), "backup scrypt r {}", self.r);
        ensure!((1..=4).contains(&self.p), "backup scrypt p {}", self.p);
        let salt = hex::decode(&self.salt).context("read the backup's salt")?;
        ensure!(
            salt.len() == 16,
            "the backup's salt is {} bytes",
            salt.len()
        );
        let params = Params::new(self.log_n, self.r, self.p, 32)
            .map_err(|e| anyhow!("backup scrypt parameters: {e}"))?;
        let mut key = [0u8; 32];
        scrypt(password.as_bytes(), &salt, &params, &mut key)
            .map_err(|e| anyhow!("stretch the backup passphrase: {e}"))?;
        Ok(key)
    }

    fn prefix(&self) -> Result<[u8; 8]> {
        let prefix = hex::decode(&self.nonce).context("read the backup's nonce")?;
        ensure!(
            prefix.len() == 8,
            "the backup's nonce prefix is {} bytes",
            prefix.len()
        );
        Ok(prefix.try_into().expect("the length was checked"))
    }

    fn chunk_bytes(&self) -> Result<usize> {
        ensure!(
            (1..=(16u64 << 20)).contains(&self.chunk),
            "backup encryption chunk {}",
            self.chunk
        );
        Ok(self.chunk as usize)
    }

    fn nonce(prefix: &[u8; 8], counter: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(prefix);
        nonce[8..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("read /dev/urandom")?;
    Ok(bytes)
}

/// The encrypted stream written over `W`: each chunk is its ciphertext's
/// length, then the ciphertext with its tag.
struct Encryptor<W> {
    inner: W,
    key: [u8; 32],
    prefix: [u8; 8],
    counter: u32,
    buffer: Vec<u8>,
    chunk: usize,
    meta: Encryption,
}

impl<W: Write> Encryptor<W> {
    fn new(inner: W, key: [u8; 32], meta: Encryption) -> Result<Encryptor<W>> {
        let prefix = meta.prefix()?;
        let chunk = meta.chunk_bytes()?;
        Ok(Encryptor {
            inner,
            key,
            prefix,
            counter: 0,
            buffer: Vec::with_capacity(chunk),
            chunk,
            meta,
        })
    }

    fn seal(&mut self, chunk: &[u8]) -> io::Result<()> {
        let nonce = Encryption::nonce(&self.prefix, self.counter);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), chunk)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encrypt a backup chunk"))?;
        if sealed.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "an encrypted chunk is too large",
            ));
        }
        self.inner.write_all(&(sealed.len() as u32).to_le_bytes())?;
        self.inner.write_all(&sealed)?;
        self.counter = self.counter.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the backup's nonce counter ran out",
            )
        })?;
        Ok(())
    }

    fn finish(mut self) -> Result<(W, Encryption)> {
        if !self.buffer.is_empty() {
            let last = std::mem::take(&mut self.buffer);
            self.seal(&last).context("finish encrypting the backup")?;
        }
        Ok((self.inner, self.meta))
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len();
        self.buffer.extend_from_slice(buf);
        while self.buffer.len() >= self.chunk {
            let chunk: Vec<u8> = self.buffer[..self.chunk].to_vec();
            self.seal(&chunk)?;
            self.buffer.drain(..self.chunk);
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The encrypted stream read back from `R`.
struct Decryptor<R> {
    inner: R,
    key: [u8; 32],
    prefix: [u8; 8],
    counter: u32,
    chunk: usize,
    plain: Vec<u8>,
    at: usize,
}

impl<R: Read> Decryptor<R> {
    fn new(inner: R, key: [u8; 32], meta: &Encryption) -> Result<Decryptor<R>> {
        Ok(Decryptor {
            inner,
            key,
            prefix: meta.prefix()?,
            counter: 0,
            chunk: meta.chunk_bytes()?,
            plain: Vec::new(),
            at: 0,
        })
    }

    fn next_chunk(&mut self) -> io::Result<bool> {
        let mut head = [0u8; 4];
        loop {
            match self.inner.read(&mut head[..1]) {
                Ok(0) => return Ok(false),
                Ok(_) => {
                    self.inner.read_exact(&mut head[1..])?;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        let len = u32::from_le_bytes(head) as usize;
        if len < 16 || len > self.chunk + 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("encrypted backup chunk of {len} bytes"),
            ));
        }
        let mut sealed = vec![0u8; len];
        self.inner.read_exact(&mut sealed)?;
        let nonce = Encryption::nonce(&self.prefix, self.counter);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let plain = cipher
            .decrypt(Nonce::from_slice(&nonce), sealed.as_slice())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decrypt a backup chunk: wrong passphrase or changed file",
                )
            })?;
        if plain.len() > self.chunk {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decrypted backup chunk is too large",
            ));
        }
        self.counter = self.counter.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the backup's nonce counter ran out",
            )
        })?;
        self.plain = plain;
        self.at = 0;
        Ok(true)
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.at < self.plain.len() {
                let n = (self.plain.len() - self.at).min(buf.len());
                buf[..n].copy_from_slice(&self.plain[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            if !self.next_chunk()? {
                return Ok(0);
            }
        }
    }
}

/// Files in `folder` named `<name>.000` on, each cut at `limit` bytes and
/// given what `ownership` says.
struct Files {
    folder: PathBuf,
    name: String,
    ownership: Ownership,
    limit: u64,
    open: Option<File>,
    in_open: u64,
    names: Vec<String>,
    written: u64,
}

impl Files {
    /// Write the file open to the storage, and make the next one.
    fn next(&mut self) -> io::Result<()> {
        if let Some(full) = self.open.take() {
            full.sync_all()?;
        }
        let name = format!("{}.{:03}", self.name, self.names.len());
        let file = skyward_files::make_file(&self.folder.join(&name), self.ownership)
            .map_err(io::Error::other)?;
        self.names.push(name);
        self.open = Some(file);
        self.in_open = 0;
        Ok(())
    }

    /// Write what is left to the storage, and give the names of the files.
    fn finish(mut self) -> io::Result<(Vec<String>, u64)> {
        if self.open.is_none() {
            self.next()?;
        }
        if let Some(last) = self.open.take() {
            last.sync_all()?;
        }
        Ok((self.names, self.written))
    }
}

impl Write for Files {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.open.is_none() || self.in_open == self.limit {
            self.next()?;
        }
        let room = (self.limit - self.in_open).min(buf.len() as u64) as usize;
        let n = self
            .open
            .as_mut()
            .expect("a file is open")
            .write(&buf[..room])?;
        self.in_open += n as u64;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.open.as_mut().map_or(Ok(()), |f| f.flush())
    }
}

enum Sink {
    Plain(Files),
    Lz4(FrameEncoder<Files>),
    Encrypted(Encryptor<Files>),
    Lz4Encrypted(FrameEncoder<Encryptor<Files>>),
}

/// A part being written to its files.
pub struct Writer {
    sink: Sink,
    digest: Sha256,
    md5: Md5,
    size: u64,
}

impl Writer {
    /// Begin the part called `name` in the backup's `folder`, its files
    /// given what `ownership` says, encrypted under `password` when one is
    /// given.
    pub fn create(
        folder: &Path,
        name: &str,
        compress: bool,
        ownership: Ownership,
        password: Option<&str>,
    ) -> Result<Writer> {
        Writer::build(folder, name, compress, ownership, FILE_BYTES, password)
    }

    #[cfg(test)]
    fn cut_at(
        folder: &Path,
        name: &str,
        compress: bool,
        ownership: Ownership,
        limit: u64,
    ) -> Writer {
        Writer::build(folder, name, compress, ownership, limit, None)
            .expect("an unencrypted part is written")
    }

    fn build(
        folder: &Path,
        name: &str,
        compress: bool,
        ownership: Ownership,
        limit: u64,
        password: Option<&str>,
    ) -> Result<Writer> {
        let encryption = match password {
            Some(_) => Some(Encryption::new()?),
            None => None,
        };
        let key = match (password, &encryption) {
            (Some(password), Some(encryption)) => Some(encryption.derive(password)?),
            _ => None,
        };
        let files = Files {
            folder: folder.to_path_buf(),
            name: name.into(),
            ownership,
            limit,
            open: None,
            in_open: 0,
            names: Vec::new(),
            written: 0,
        };
        let info = FrameInfo::new()
            .block_size(BlockSize::Max4MB)
            .content_checksum(true);
        let sink = match (compress, key, encryption.clone()) {
            (false, None, _) => Sink::Plain(files),
            (true, None, _) => Sink::Lz4(FrameEncoder::with_frame_info(info, files)),
            (false, Some(key), Some(meta)) => Sink::Encrypted(Encryptor::new(files, key, meta)?),
            (true, Some(key), Some(meta)) => Sink::Lz4Encrypted(FrameEncoder::with_frame_info(
                info,
                Encryptor::new(files, key, meta)?,
            )),
            _ => unreachable!("an encrypted part has a key and its metadata"),
        };
        Ok(Writer {
            sink,
            digest: Sha256::new(),
            md5: Md5::new(),
            size: 0,
        })
    }

    /// Write the rest to the storage, and give what the part's files keep.
    pub fn finish(self) -> Result<Stored> {
        let (files, compressed, encryption) = match self.sink {
            Sink::Plain(files) => (files, false, None),
            Sink::Lz4(encoder) => (encoder.finish().context("finish compressing")?, true, None),
            Sink::Encrypted(encoder) => {
                let (files, encryption) = encoder.finish()?;
                (files, false, Some(encryption))
            }
            Sink::Lz4Encrypted(encoder) => {
                let encoder = encoder.finish().context("finish compressing")?;
                let (files, encryption) = encoder.finish()?;
                (files, true, Some(encryption))
            }
        };
        let (files, stored) = files.finish().context("write the backup's files")?;
        Ok(Stored {
            files,
            size: self.size,
            stored,
            compressed,
            sha256: hex::encode(self.digest.finalize()),
            md5: hex::encode(self.md5.finalize()),
            encryption,
        })
    }
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = match &mut self.sink {
            Sink::Plain(files) => files.write(buf)?,
            Sink::Lz4(encoder) => encoder.write(buf)?,
            Sink::Encrypted(encoder) => encoder.write(buf)?,
            Sink::Lz4Encrypted(encoder) => encoder.write(buf)?,
        };
        self.digest.update(&buf[..n]);
        self.md5.update(&buf[..n]);
        self.size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.sink {
            Sink::Plain(files) => files.flush(),
            Sink::Lz4(encoder) => encoder.flush(),
            Sink::Encrypted(encoder) => encoder.flush(),
            Sink::Lz4Encrypted(encoder) => encoder.flush(),
        }
    }
}

/// A part's files read one after another, as one.
struct Joined {
    folder: PathBuf,
    names: Vec<String>,
    next: usize,
    open: Option<BufReader<File>>,
}

impl Read for Joined {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(file) = &mut self.open {
                let n = file.read(buf)?;
                if n > 0 || buf.is_empty() {
                    return Ok(n);
                }
            }
            let Some(name) = self.names.get(self.next) else {
                return Ok(0);
            };
            let path = self.folder.join(name);
            let file = File::open(&path)
                .map_err(|e| io::Error::new(e.kind(), format!("open {}: {e}", path.display())))?;
            self.open = Some(BufReader::with_capacity(1 << 20, file));
            self.next += 1;
        }
    }
}

/// A part read back from its files, what it holds counted and digested as
/// it goes.
pub struct Reader {
    source: Box<dyn Read + Send>,
    digest: Sha256,
    md5: Md5,
    size: u64,
}

impl Reader {
    pub fn open(folder: &Path, stored: &Stored, password: Option<&str>) -> Result<Reader> {
        let joined = Joined {
            folder: folder.to_path_buf(),
            names: stored.files.clone(),
            next: 0,
            open: None,
        };
        let source: Box<dyn Read + Send> = match &stored.encryption {
            Some(encryption) => {
                let password =
                    password.context("the backup is encrypted and needs its passphrase")?;
                Box::new(Decryptor::new(
                    joined,
                    encryption.derive(password)?,
                    encryption,
                )?)
            }
            None => Box::new(joined),
        };
        let source: Box<dyn Read + Send> = match stored.compressed {
            true => Box::new(FrameDecoder::new(source)),
            false => source,
        };
        Ok(Reader {
            source,
            digest: Sha256::new(),
            md5: Md5::new(),
            size: 0,
        })
    }

    /// Once all of it is read: whether it is what was stored.
    pub fn check(self, stored: &Stored) -> Result<()> {
        ensure!(
            self.size == stored.size,
            "the backup holds {} bytes where {} were stored",
            self.size,
            stored.size
        );
        let digest = hex::encode(self.digest.finalize());
        ensure!(
            digest == stored.sha256,
            "the backup does not hold what was stored: its digest is {digest}, {} was stored",
            stored.sha256
        );
        let md5 = hex::encode(self.md5.finalize());
        ensure!(
            stored.md5.is_empty() || md5 == stored.md5,
            "the backup does not hold what was stored: its MD5 is {md5}, {} was stored",
            stored.md5
        );
        Ok(())
    }
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.source.read(buf)?;
        self.digest.update(&buf[..n]);
        self.md5.update(&buf[..n]);
        self.size += n as u64;
        Ok(n)
    }
}

/// The SHA-256 and MD5 of the first `len` bytes `from` gives, in hex as a
/// part's are kept: a partition read back once a part is written to it, to
/// see that it holds the part. Tells how many bytes are read so far.
pub fn digests(
    mut from: impl Read,
    len: u64,
    progress: &mut dyn FnMut(u64),
) -> io::Result<(String, String)> {
    let mut digest = Sha256::new();
    let mut md5 = Md5::new();
    let mut buf = vec![0u8; 4 << 20];
    let mut done = 0u64;
    while done < len {
        let want = (len - done).min(buf.len() as u64) as usize;
        from.read_exact(&mut buf[..want])?;
        digest.update(&buf[..want]);
        md5.update(&buf[..want]);
        done += want as u64;
        progress(done);
    }
    Ok((hex::encode(digest.finalize()), hex::encode(md5.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(test: &str) -> PathBuf {
        let at = std::env::temp_dir().join(format!("skyward-store-{test}-{}", std::process::id()));
        if at.exists() {
            fs::remove_dir_all(&at).unwrap();
        }
        fs::create_dir_all(&at).unwrap();
        at
    }

    /// Bytes that compress some way but not all the way.
    fn sample(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8 ^ (i / 997) as u8).collect()
    }

    #[test]
    fn a_part_is_cut_into_files_and_read_back_whole() {
        let at = scratch("cut");
        for compress in [false, true] {
            let name = if compress { "packed" } else { "plain" };
            let held = sample(2_500);
            let mut w = Writer::cut_at(&at, name, compress, Ownership::Kept, 1_000);
            w.write_all(&held).unwrap();
            let stored = w.finish().unwrap();
            assert_eq!((stored.size, stored.compressed), (2_500, compress));
            if !compress {
                assert_eq!(
                    stored.files,
                    ["plain.000", "plain.001", "plain.002"],
                    "cut at the limit"
                );
                assert_eq!(stored.stored, 2_500);
            }
            assert_eq!(stored.md5.len(), 32);
            let mut r = Reader::open(&at, &stored, None).unwrap();
            let mut back = Vec::new();
            r.read_to_end(&mut back).unwrap();
            assert_eq!(back, held);
            r.check(&stored).unwrap();
        }
        fs::remove_dir_all(&at).unwrap();
    }

    #[test]
    fn a_part_that_changed_after_it_was_stored_fails_its_check() {
        let at = scratch("changed");
        let mut w = Writer::cut_at(&at, "boot", false, Ownership::Kept, 1_000);
        w.write_all(&sample(1_500)).unwrap();
        let stored = w.finish().unwrap();
        let second = at.join("boot.001");
        let mut bytes = fs::read(&second).unwrap();
        bytes[10] ^= 1;
        fs::write(&second, bytes).unwrap();
        let mut r = Reader::open(&at, &stored, None).unwrap();
        io::copy(&mut r, &mut io::sink()).unwrap();
        assert!(r.check(&stored).is_err());
        fs::remove_file(&second).unwrap();
        let mut r = Reader::open(&at, &stored, None).unwrap();
        assert!(
            io::copy(&mut r, &mut io::sink()).is_err(),
            "a file gone is an error"
        );
        fs::remove_dir_all(&at).unwrap();
    }

    #[test]
    fn what_is_read_back_digests_as_the_part_was_stored() {
        let at = scratch("digest");
        let held = sample(3_000);
        let mut w = Writer::cut_at(&at, "dtbo", true, Ownership::Kept, 1_000);
        w.write_all(&held).unwrap();
        let stored = w.finish().unwrap();
        // A partition is larger than what went into it; only the part's
        // bytes count.
        let mut partition = held.clone();
        partition.extend([0xff; 512]);
        let mut told = 0;
        assert_eq!(
            digests(partition.as_slice(), stored.size, &mut |n| told = n).unwrap(),
            (stored.sha256.clone(), stored.md5.clone())
        );
        assert_eq!(told, 3_000);
        partition[2_999] ^= 1;
        assert_ne!(
            digests(partition.as_slice(), stored.size, &mut |_| {})
                .unwrap()
                .0,
            stored.sha256
        );
        assert!(
            digests(&held[..10], stored.size, &mut |_| {}).is_err(),
            "a partition too small to hold the part"
        );
        fs::remove_dir_all(&at).unwrap();
    }

    #[test]
    fn an_encrypted_part_reads_back_only_with_its_passphrase() {
        let at = scratch("encrypted");
        for compress in [false, true] {
            let name = if compress { "packed" } else { "plain" };
            // Past two encryption chunks, and not a whole one at the end.
            let held = sample((2 * Encryption::CHUNK as usize) + 1);
            let mut w = Writer::create(
                &at,
                name,
                compress,
                Ownership::Kept,
                Some("a passphrase worth keeping"),
            )
            .unwrap();
            w.write_all(&held).unwrap();
            let stored = w.finish().unwrap();
            let encryption = stored.encryption.as_ref().expect("the part is encrypted");
            assert_eq!(encryption.cipher, Encryption::CIPHER);
            assert_eq!(stored.md5.len(), 32);
            assert!(stored.stored > 0, "the part is kept");
            assert!(
                Reader::open(&at, &stored, None).is_err(),
                "no passphrase, no reading"
            );
            let mut r = Reader::open(&at, &stored, Some("a passphrase worth keeping")).unwrap();
            let mut back = Vec::new();
            r.read_to_end(&mut back).unwrap();
            assert_eq!(back, held);
            r.check(&stored).unwrap();
            let mut r = Reader::open(&at, &stored, Some("another passphrase")).unwrap();
            assert!(
                io::copy(&mut r, &mut io::sink()).is_err(),
                "the wrong passphrase does not open it"
            );
        }
        fs::remove_dir_all(&at).unwrap();
    }

    #[test]
    fn an_empty_encrypted_part_reads_back() {
        let at = scratch("encrypted-empty");
        let stored = Writer::create(&at, "empty", true, Ownership::Kept, Some("a passphrase"))
            .unwrap()
            .finish()
            .unwrap();
        assert!(stored.encryption.is_some());
        let mut r = Reader::open(&at, &stored, Some("a passphrase")).unwrap();
        assert_eq!(io::copy(&mut r, &mut io::sink()).unwrap(), 0);
        r.check(&stored).unwrap();
        fs::remove_dir_all(&at).unwrap();
    }

    #[test]
    fn a_part_whose_md5_changed_fails_its_check() {
        let at = scratch("md5");
        let mut w = Writer::cut_at(&at, "boot", false, Ownership::Kept, 1_000);
        w.write_all(&sample(1_500)).unwrap();
        let mut stored = w.finish().unwrap();
        stored.md5 = "00".repeat(16);
        let mut r = Reader::open(&at, &stored, None).unwrap();
        io::copy(&mut r, &mut io::sink()).unwrap();
        let e = r.check(&stored).unwrap_err();
        assert!(e.to_string().contains("its MD5 is"), "{e:#}");
        fs::remove_dir_all(&at).unwrap();
    }

    #[test]
    fn an_encrypted_part_changed_on_the_storage_fails_its_check() {
        let at = scratch("encrypted-changed");
        let held = sample(5_000);
        let mut w =
            Writer::create(&at, "boot", false, Ownership::Kept, Some("a passphrase")).unwrap();
        w.write_all(&held).unwrap();
        let stored = w.finish().unwrap();
        let file = at.join(&stored.files[0]);
        let mut bytes = fs::read(&file).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&file, bytes).unwrap();
        let mut r = Reader::open(&at, &stored, Some("a passphrase")).unwrap();
        assert!(
            io::copy(&mut r, &mut io::sink()).is_err(),
            "a changed ciphertext does not decrypt"
        );
        fs::remove_dir_all(&at).unwrap();
    }

    #[test]
    fn encryption_parameters_from_a_manifest_are_kept_inside_what_a_phone_takes() {
        let at = scratch("parameters");
        let stored = Writer::create(&at, "boot", false, Ownership::Kept, Some("a passphrase"))
            .unwrap()
            .finish()
            .unwrap();
        let mut meta = stored.encryption.unwrap();
        for (log_n, r, p) in [(20, 8, 1), (15, 64, 1), (15, 8, 16)] {
            meta.log_n = log_n;
            meta.r = r;
            meta.p = p;
            assert!(meta.derive("a passphrase").is_err(), "{log_n}/{r}/{p}");
        }
        meta.log_n = 15;
        meta.r = 8;
        meta.p = 1;
        meta.salt = "0011".into();
        assert!(meta.derive("a passphrase").is_err(), "a short salt");
        fs::remove_dir_all(&at).unwrap();
    }

    #[test]
    fn an_empty_part_still_has_a_file() {
        let at = scratch("empty");
        let stored = Writer::cut_at(&at, "fsc", true, Ownership::Kept, 1_000)
            .finish()
            .unwrap();
        assert_eq!(stored.files, ["fsc.000"]);
        let mut r = Reader::open(&at, &stored, None).unwrap();
        assert_eq!(io::copy(&mut r, &mut io::sink()).unwrap(), 0);
        r.check(&stored).unwrap();
        fs::remove_dir_all(&at).unwrap();
    }
}
