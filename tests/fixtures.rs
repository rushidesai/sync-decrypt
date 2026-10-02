//! Decrypt the sample files from the reference implementation's test suite.

use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_syno-decrypt");

fn fixture(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(rel)
}

fn password() -> String {
    std::fs::read_to_string(fixture("testfiles-secrets/password.txt")).unwrap()
}

fn decrypt(password: &str, input: &str) -> std::process::Output {
    Command::new(BIN)
        .args(["-p", password, "-f"])
        .arg(fixture(input))
        .args(["-o", "-"])
        .output()
        .unwrap()
}

#[test]
fn decrypts_reference_files() {
    for (enc, plain) in [
        ("testfiles-csenc/single-line.txt", "testfiles-plain/single-line.txt"),
        ("testfiles-v1/csenc/single-line.txt", "testfiles-v1/plain/single-line.txt"),
        ("testfiles-v3/csenc/ssingle-line.txt", "testfiles-v3/plain/ssingle-line.txt"),
    ] {
        let out = decrypt(&password(), enc);
        assert!(out.status.success(), "{enc}: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.stdout, std::fs::read(fixture(plain)).unwrap(), "{enc}");
    }
}

#[test]
fn rejects_wrong_password() {
    let out = decrypt("nope", "testfiles-v3/csenc/ssingle-line.txt");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("wrong password"));
}
