use miette::{IntoDiagnostic, Result};
use tap::Pipe as _;
use tokio::io::BufReader;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut stdin = tokio::io::stdin().pipe(BufReader::new);
    let mut stdout = tokio::io::stdout();

    zconned::run(&mut stdin, &mut stdout)
        .await
        .into_diagnostic()?;
    Ok(())
}
