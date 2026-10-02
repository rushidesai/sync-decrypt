# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`syno-decrypt` is a Rust CLI that decrypts Synology Cloud Sync encrypted files (`__CLOUDSYNC_ENC__` format, versions 1.0 / 3.0 / 3.1) using a password. It is a port of the Python tool at https://github.com/anojht/synology-cloud-sync-decrypt-tool (`syndecrypt/core.py`, `syndecrypt/util.py`), which is GPL-3.0. Check that implementation when the format behaves unexpectedly.

## Commands

```sh
cargo build
cargo test                                   # unit tests (src/csenc.rs) + fixture tests (tests/fixtures.rs)
cargo test decrypts_reference_files          # run a single test by name
cargo run -- -f tests/fixtures/testfiles-v3/csenc/ssingle-line.txt -o - -p "$(cat tests/fixtures/testfiles-secrets/password.txt)"
```

Clippy isn't installed on this toolchain (`rustup component add clippy` adds it).

## CLI contract

- `-f/--file` defaults to stdin and `-o/--output` defaults to stdout; `-` also means stdin/stdout.
- `-p/--password` is optional. Without it, the password is prompted for on the TTY via `rpassword`, which reads `/dev/tty`, so prompting works while stdin carries the data.
- The tool refuses to write to stdout when it's a terminal, or to read stdin when it's a terminal.
- `CsencReader::new` checks the header and password *before* the output file is created, so a wrong password never truncates an existing file. If decryption fails after the output file exists (corruption, MD5 mismatch), the file is deleted.

## Architecture

Decryption is a pull pipeline of `Read` adapters, so files of any size stream without being held in memory:

```
input -> BufReader -> CsencReader (parse objects + AES-256-CBC) -> lz4_flex FrameDecoder -> HashingWriter (MD5) -> BufWriter -> output
```

- **`src/csenc.rs`**: the file format.
  - After the magic and its hex MD5, the file is a stream of tagged objects: `0x42` dict (ends with `0x40`), `0x10` string, `0x11` bytes (u16 BE length), `0x01` int (u8 length + BE bytes). A top-level `0x40` or EOF ends the stream.
  - Top-level dicts have `type` = `metadata` or `data`.
  - `CsencReader::new` reads every metadata object up to the first data chunk, then checks `key1_hash` (password) and derives the session key.
  - Its `Read` impl pulls further objects lazily. Trailing metadata, in particular `file_md5`, comes *after* the data, so `expected_md5()` is only valid once the reader has hit EOF.
  - The final decrypted block is held back until end of stream so its PKCS#7 padding can be stripped.
- **Key derivation**: OpenSSL `EVP_BytesToKey` with MD5 (`openssl_kdf`), using 1000 iterations when a salt is present and 1 otherwise.
  - `enc_key1` is decrypted with KDF(password, salt).
  - In v3 (salted) files the result is a hex string that must be hex-decoded. In v1 it's used raw.
  - Data is decrypted with KDF(session_key, no salt).
  - `session_key_hash` is checked against the session key *before* hex-decoding.
- **`src/main.rs`**: CLI handling, I/O setup, and the LZ4 and MD5 stages. LZ4 is skipped when metadata says `compress: 0`. `lz4_flex::FrameDecoder` handles concatenated frames.

## Tests and fixtures

`tests/fixtures/` holds real Synology-encrypted samples copied from the upstream repo's `tests/` directory (GPL-3.0). The password is in `testfiles-secrets/password.txt`. `private.pem` is for the planned `-k` option (see Future work). All fixtures are single-chunk, so the multi-chunk path (`push_ciphertext` carry/compaction) isn't covered by real data.

## Future work

### `-k/--key FILE`: decrypt with an RSA private key instead of a password

Cloud Sync stores the session key twice: `enc_key1` is encrypted with the password, and `enc_key2` is encrypted with the RSA public key from the key pair Synology lets you export. The upstream `decrypted_with_private_key` supports the second path; this tool doesn't yet. Suggested design:

- **CLI:** add `-k/--key FILE` (a PEM private key), mutually exclusive with `-p` (clap `conflicts_with`). When `-k` is given, skip the password prompt.
- **Decryption:** upstream base64-decodes `enc_key2` and decrypts it with RSA PKCS#1 OAEP using SHA-1 (PyCryptodome's `PKCS1_OAEP` default). In Rust that's the `rsa` crate with `Oaep::new::<sha1::Sha1>()`. Upstream reads the key with `RSA.importKey`, which accepts both PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8 (`BEGIN PRIVATE KEY`) PEM, so try both.
- **After that, reuse the password flow:** the decrypted value is the same session key `enc_key1` yields, so the `session_key_hash` check, the v3 hex-decode and `cipher_for(&session_key, b"")` stay the same. The cleanest refactor is to have `CsencReader::new` take an enum like `Credential::Password(String) | Credential::PrivateKey(RsaPrivateKey)`, and parse `enc_key2` in `Metadata::absorb` alongside `enc_key1`.
- **Checks:** upstream doesn't verify `key2_hash` (it's a TODO there), so there's no known fast "wrong key" check. A wrong key surfaces as an OAEP decryption failure; report that as "wrong private key".
- **Tests:** add `-k tests/fixtures/testfiles-secrets/private.pem` cases to `tests/fixtures.rs`, covering all three samples. Upstream's tests use this key, but whether it matches every sample hasn't been confirmed here.
