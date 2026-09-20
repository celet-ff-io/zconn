use miette::{IntoDiagnostic, Result};
use tokio::io::{BufReader, BufWriter};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = BufWriter::new(tokio::io::stdout());

    zconned::run(&mut stdin, &mut stdout)
        .await
        .into_diagnostic()?;
    Ok(())
}
