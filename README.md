# syno-decrypt

Decrypt files encrypted by Synology Cloud Sync (`__CLOUDSYNC_ENC__` format,
versions 1.0, 3.0 and 3.1) using the encryption password.

```sh
cargo install --path .

syno-decrypt -f photo.jpg -o photo.dec.jpg      # prompts for password
syno-decrypt -p 'secret' < enc.bin > plain.bin  # stdin -> stdout
```

| Flag | Meaning | Default |
|------|---------|---------|
| `-f, --file FILE` | encrypted input | stdin |
| `-o, --output FILE` | decrypted output | stdout |
| `-p, --password PW` | password (ends up in shell history / `ps`) | prompt on the terminal |

`-` for `-f` / `-o` also means stdin / stdout. The password is checked before
the output file is created; the MD5 stored in the file is verified at the end
and the output file is deleted if it doesn't match.

Ported from
[anojht/synology-cloud-sync-decrypt-tool](https://github.com/anojht/synology-cloud-sync-decrypt-tool)
(GPL-3.0); the sample files in `tests/fixtures` come from that project.
