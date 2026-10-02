//! Decoder for Synology Cloud Sync encrypted files (`__CLOUDSYNC_ENC__`).
//!
//! File layout: a magic string, the hex MD5 of that magic, then a sequence of
//! serialized dictionaries. Metadata dicts carry the key material (`enc_key1`,
//! `salt`, `version`, ...); data dicts carry chunks of AES-256-CBC ciphertext.
//! The decrypted stream is (usually) an LZ4 frame holding the original file.
//!
//! Ported from https://github.com/anojht/synology-cloud-sync-decrypt-tool

use std::io::{self, Read};

use aes::Aes256;
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use cbc::cipher::{Block, BlockModeDecrypt, KeyIvInit};
use md5::{Digest, Md5};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

const MAGIC: &[u8] = b"__CLOUDSYNC_ENC__";
const BLOCK: usize = 16;

/// A value in the Cloud Sync object serialization.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    Int(u64),
    Str(String),
    Bytes(Vec<u8>),
    Dict(Vec<(Value, Value)>),
}

impl Value {
    fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(entries) => entries
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_int(&self) -> Option<u64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
}

/// Result of reading one tag from the stream.
enum Item {
    Value(Value),
    /// 0x40: terminates a dict, or the whole stream at top level.
    End,
    /// Clean end of input.
    Eof,
}

fn read_exact_vec<R: Read>(r: &mut R, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).context("unexpected end of file")?;
    Ok(buf)
}

fn read_item<R: Read>(r: &mut R) -> Result<Item> {
    let mut tag = [0u8; 1];
    loop {
        match r.read(&mut tag) {
            Ok(0) => return Ok(Item::Eof),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let value = match tag[0] {
        0x40 => return Ok(Item::End),
        0x42 => {
            let mut entries = Vec::new();
            loop {
                let key = match read_item(r)? {
                    Item::Value(v) => v,
                    Item::End => break,
                    Item::Eof => bail!("unexpected end of file inside dict"),
                };
                let value = match read_item(r)? {
                    Item::Value(v) => v,
                    _ => bail!("dict key without a value"),
                };
                entries.push((key, value));
            }
            Value::Dict(entries)
        }
        0x10 | 0x11 => {
            let len = read_exact_vec(r, 2)?;
            let bytes = read_exact_vec(r, u16::from_be_bytes([len[0], len[1]]) as usize)?;
            if tag[0] == 0x10 {
                Value::Str(String::from_utf8(bytes).context("invalid UTF-8 string")?)
            } else {
                Value::Bytes(bytes)
            }
        }
        0x01 => {
            let len = read_exact_vec(r, 1)?[0] as usize;
            ensure!(len <= 8, "integer of {len} bytes is too large");
            let bytes = read_exact_vec(r, len)?;
            Value::Int(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
        }
        t => bail!("unknown type byte 0x{t:02X}"),
    };
    Ok(Item::Value(value))
}

fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

/// OpenSSL's EVP_BytesToKey with MD5, as used by `openssl enc`.
fn openssl_kdf(password: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 16]) {
    let count = if salt.is_empty() { 1 } else { 1000 };
    let mut out = Vec::with_capacity(48);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < 48 {
        let mut h = [prev.as_slice(), password, salt].concat();
        for _ in 0..count {
            h = md5(&h).to_vec();
        }
        out.extend_from_slice(&h);
        prev = h;
    }
    (out[..32].try_into().unwrap(), out[32..48].try_into().unwrap())
}

fn cipher_for(password: &[u8], salt: &[u8]) -> Aes256CbcDec {
    let (key, iv) = openssl_kdf(password, salt);
    Aes256CbcDec::new_from_slices(&key, &iv).expect("valid key/iv length")
}

/// Decrypt whole blocks in place. `data.len()` must be a multiple of 16.
fn decrypt_blocks(cipher: &mut Aes256CbcDec, data: &mut [u8]) {
    for chunk in data.chunks_exact_mut(BLOCK) {
        let mut block = Block::<Aes256CbcDec>::try_from(&*chunk).unwrap();
        cipher.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
}

fn pkcs7_unpad_len(data: &[u8]) -> Option<usize> {
    let pad = *data.last()? as usize;
    if pad == 0 || pad > BLOCK || pad > data.len() {
        return None;
    }
    data[data.len() - pad..]
        .iter()
        .all(|&b| b as usize == pad)
        .then(|| data.len() - pad)
}

/// `salt + md5hex(salt + data)`, where salt is the first 10 chars of `expected`.
fn salted_hash_matches(expected: &str, data: &[u8]) -> bool {
    let Some(salt) = expected.get(..10) else {
        return false;
    };
    let digest = md5(&[salt.as_bytes(), data].concat());
    expected[10..] == hex::encode(digest)
}

#[derive(Debug, Default)]
struct Metadata {
    compress: Option<u64>,
    digest: Option<String>,
    enc_key1: Option<Vec<u8>>,
    key1_hash: Option<String>,
    salt: Vec<u8>,
    session_key_hash: Option<String>,
    version: Option<(u64, u64)>,
    file_md5: Option<String>,
}

impl Metadata {
    fn absorb(&mut self, dict: &Value) -> Result<()> {
        let Value::Dict(entries) = dict else {
            unreachable!()
        };
        for (k, v) in entries {
            let str_value = || {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("metadata field {k:?} is not a string"))
            };
            match k.as_str() {
                Some("compress") => self.compress = v.as_int(),
                Some("digest") => self.digest = Some(str_value()?),
                Some("enc_key1") => {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(str_value()?)
                        .context("enc_key1 is not valid base64")?;
                    self.enc_key1 = Some(decoded);
                }
                Some("key1_hash") => self.key1_hash = Some(str_value()?),
                Some("salt") => self.salt = str_value()?.into_bytes(),
                Some("session_key_hash") => self.session_key_hash = Some(str_value()?),
                Some("file_md5") => self.file_md5 = Some(str_value()?),
                Some("version") => {
                    let major = v.get("major").and_then(Value::as_int);
                    let minor = v.get("minor").and_then(Value::as_int);
                    match (major, minor) {
                        (Some(a), Some(b)) => self.version = Some((a, b)),
                        _ => bail!("malformed version field: {v:?}"),
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Streaming reader over the decrypted (but still possibly LZ4-compressed)
/// payload of a Cloud Sync encrypted file.
pub struct CsencReader<R> {
    input: R,
    cipher: Aes256CbcDec,
    meta: Metadata,
    /// Ciphertext bytes waiting for a full block.
    carry: Vec<u8>,
    /// Decrypted bytes; `pending[pos..]` not yet returned. The last block is
    /// held back until end of stream so its PKCS#7 padding can be stripped.
    pending: Vec<u8>,
    pos: usize,
    done: bool,
}

impl<R: Read> CsencReader<R> {
    /// Parse the header and metadata, check the password, and position the
    /// reader at the start of the payload.
    pub fn new(mut input: R, password: &str) -> Result<Self> {
        let mut magic = [0u8; MAGIC.len()];
        input
            .read_exact(&mut magic)
            .context("file too short to be a Cloud Sync encrypted file")?;
        ensure!(
            magic == MAGIC,
            "not a Cloud Sync encrypted file (missing __CLOUDSYNC_ENC__ header; note that \
             files from Synology encrypted shared folders use eCryptfs, a different format)"
        );
        let magic_hash = read_exact_vec(&mut input, 32)?;
        ensure!(
            magic_hash == hex::encode(md5(MAGIC)).as_bytes(),
            "corrupt header: bad magic hash"
        );

        let mut meta = Metadata::default();
        let first_chunk = loop {
            let obj = match read_item(&mut input)? {
                Item::Value(v @ Value::Dict(_)) => v,
                Item::Value(v) => bail!("expected a dict at top level, found {v:?}"),
                Item::End | Item::Eof => break None,
            };
            match obj.get("type").and_then(Value::as_str) {
                Some("metadata") => meta.absorb(&obj)?,
                Some("data") => match obj.get("data") {
                    Some(Value::Bytes(b)) => break Some(b.clone()),
                    _ => bail!("data object without data bytes"),
                },
                other => bail!("unknown object type {other:?}"),
            }
        };

        if let Some(version) = meta.version {
            ensure!(
                matches!(version, (1, 0) | (3, 0) | (3, 1)),
                "unsupported file format version {}.{}",
                version.0,
                version.1
            );
        }

        if let Some(expected) = &meta.key1_hash {
            ensure!(
                salted_hash_matches(expected, password.as_bytes()),
                "wrong password"
            );
        }

        let mut enc_key1 = meta
            .enc_key1
            .clone()
            .ok_or_else(|| anyhow!("file has no enc_key1; it cannot be decrypted with a password"))?;
        ensure!(
            !enc_key1.is_empty() && enc_key1.len() % BLOCK == 0,
            "malformed enc_key1"
        );
        decrypt_blocks(&mut cipher_for(password.as_bytes(), &meta.salt), &mut enc_key1);
        let len = pkcs7_unpad_len(&enc_key1).ok_or_else(|| anyhow!("wrong password"))?;
        let session_key = &enc_key1[..len];

        if let Some(expected) = &meta.session_key_hash {
            ensure!(
                salted_hash_matches(expected, session_key),
                "wrong password (session key hash mismatch)"
            );
        }

        // Version 3+ (salted) files store the session key hex-encoded.
        let session_key = if meta.salt.is_empty() {
            session_key.to_vec()
        } else {
            hex::decode(session_key).context("wrong password (session key is not hex)")?
        };

        let mut reader = CsencReader {
            input,
            cipher: cipher_for(&session_key, b""),
            meta,
            carry: Vec::new(),
            pending: Vec::new(),
            pos: 0,
            done: false,
        };
        match first_chunk {
            Some(chunk) => reader.push_ciphertext(&chunk),
            None => reader.finish()?,
        }
        Ok(reader)
    }

    /// Whether the payload is LZ4-compressed (the default when unspecified).
    pub fn is_compressed(&self) -> bool {
        self.meta.compress != Some(0)
    }

    /// Expected MD5 (lowercase hex) of the plaintext, if the file records one.
    /// Only reliable after the reader has hit end of stream, since the
    /// checksum is stored after the data.
    pub fn expected_md5(&self) -> Option<&str> {
        match self.meta.digest.as_deref() {
            Some("md5") | None => self.meta.file_md5.as_deref(),
            Some(_) => None,
        }
    }

    fn push_ciphertext(&mut self, data: &[u8]) {
        self.pending.drain(..self.pos);
        self.pos = 0;
        self.carry.extend_from_slice(data);
        let whole = self.carry.len() / BLOCK * BLOCK;
        let start = self.pending.len();
        self.pending.extend(self.carry.drain(..whole));
        decrypt_blocks(&mut self.cipher, &mut self.pending[start..]);
    }

    fn finish(&mut self) -> Result<()> {
        ensure!(self.carry.is_empty(), "truncated ciphertext");
        self.done = true;
        if self.pending.is_empty() {
            return Ok(());
        }
        let len = pkcs7_unpad_len(&self.pending)
            .filter(|&len| len >= self.pos)
            .ok_or_else(|| anyhow!("bad padding at end of data (file corrupt?)"))?;
        self.pending.truncate(len);
        Ok(())
    }

    /// Read the next top-level object: buffer data, record trailing metadata.
    fn advance(&mut self) -> Result<()> {
        loop {
            let obj = match read_item(&mut self.input)? {
                Item::Value(v @ Value::Dict(_)) => v,
                Item::Value(v) => bail!("expected a dict at top level, found {v:?}"),
                Item::End | Item::Eof => return self.finish(),
            };
            match obj.get("type").and_then(Value::as_str) {
                Some("data") => match obj.get("data") {
                    Some(Value::Bytes(b)) => {
                        self.push_ciphertext(b);
                        return Ok(());
                    }
                    _ => bail!("data object without data bytes"),
                },
                Some("metadata") => self.meta.absorb(&obj)?,
                other => bail!("unknown object type {other:?}"),
            }
        }
    }
}

impl<R: Read> Read for CsencReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let ready_end = if self.done {
                self.pending.len()
            } else {
                self.pending.len().saturating_sub(BLOCK)
            };
            if self.pos < ready_end {
                let n = buf.len().min(ready_end - self.pos);
                buf[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            self.advance()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:#}")))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_matches_openssl() {
        // Unsalted case is plain EVP_BytesToKey(md5, count=1):
        // key = md5(pw) || md5(md5(pw) || pw), iv = md5(<second block> || pw).
        let (key, iv) = openssl_kdf(b"password", b"");
        assert_eq!(
            hex::encode(key),
            "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08"
        );
        assert_eq!(hex::encode(iv), "b7b4372cdfbcb3d16a2631b59b509e94");
    }

    #[test]
    fn salted_hash() {
        let salt = "abcdefghij";
        let h = format!("{salt}{}", hex::encode(md5(b"abcdefghijsecret")));
        assert!(salted_hash_matches(&h, b"secret"));
        assert!(!salted_hash_matches(&h, b"Secret"));
        assert!(!salted_hash_matches("short", b"secret"));
    }
}
