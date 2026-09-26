use miette::{IntoDiagnostic, Result, diagnostic};
use tokio::io::{BufReader, BufWriter};

fn core_bin_arg() -> Result<String> {
    let mut pending_core = false;
    for arg in std::env::args() {
        if pending_core {
            return Ok(arg);
        }
        if arg == "--core" {
            pending_core = true;
        }
    }
    Err(diagnostic!("missing `--core <path>` argument: path to the zconned binary").into())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let core_bin = core_bin_arg()?;

    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = BufWriter::new(tokio::io::stdout());

    zconned_json_translator::run(&core_bin, &mut stdin, &mut stdout)
        .await
        .into_diagnostic()?;
    Ok(())
}
