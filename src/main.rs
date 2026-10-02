mod csenc;

use std::fs::File;
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Parser;
use md5::{Digest, Md5};

use csenc::CsencReader;

/// Decrypt files encrypted by Synology Cloud Sync.
///
/// Reads from stdin and writes to stdout unless -f / -o are given
/// (`-` also means stdin/stdout). Prompts for the password on the
/// terminal unless -p is given.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Encrypted input file [default: stdin]
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    input: Option<PathBuf>,

    /// Decrypted output file [default: stdout]
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Password (visible in shell history and `ps`; omit to be prompted)
    #[arg(short, long)]
    password: Option<String>,
}

fn is_stdio(path: &Option<PathBuf>) -> bool {
    path.as_ref().is_none_or(|p| p.as_os_str() == "-")
}

/// Passes writes through while computing their MD5.
struct HashingWriter<W> {
    inner: W,
    hasher: Md5,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn decrypt<R: Read>(mut reader: CsencReader<R>, output: Box<dyn Write>) -> Result<()> {
    let mut writer = HashingWriter {
        inner: BufWriter::new(output),
        hasher: Md5::new(),
    };

    if reader.is_compressed() {
        let mut lz4 = lz4_flex::frame::FrameDecoder::new(reader);
        io::copy(&mut lz4, &mut writer).context("decryption failed")?;
        reader = lz4.into_inner();
    } else {
        io::copy(&mut reader, &mut writer).context("decryption failed")?;
    }
    writer.flush().context("failed to write output")?;

    if let Some(expected) = reader.expected_md5() {
        let actual = hex::encode(writer.hasher.finalize());
        if !actual.eq_ignore_ascii_case(expected) {
            bail!("checksum mismatch: expected MD5 {expected}, got {actual}");
        }
    }
    Ok(())
}

fn run(args: Args) -> Result<()> {
    let to_stdout = is_stdio(&args.output);
    if to_stdout && io::stdout().is_terminal() {
        bail!("refusing to write binary output to a terminal; use -o FILE or redirect stdout");
    }

    let input: Box<dyn Read> = match &args.input {
        Some(p) if !is_stdio(&args.input) => Box::new(
            File::open(p).with_context(|| format!("cannot open {}", p.display()))?,
        ),
        _ => {
            if io::stdin().is_terminal() {
                bail!("no input: use -f FILE or pipe data on stdin");
            }
            Box::new(io::stdin().lock())
        }
    };

    let password = match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Password: ").context("failed to read password")?,
    };

    // Check the header and password before touching the output file.
    let reader = CsencReader::new(BufReader::new(input), &password)?;

    if to_stdout {
        return decrypt(reader, Box::new(io::stdout().lock()));
    }

    let path = args.output.unwrap();
    let file = File::create(&path).with_context(|| format!("cannot create {}", path.display()))?;
    let result = decrypt(reader, Box::new(file));
    if result.is_err() {
        // Don't leave a truncated or unverified file behind.
        let _ = std::fs::remove_file(&path);
    }
    result
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("syno-decrypt: {e:#}");
            ExitCode::FAILURE
        }
    }
}
