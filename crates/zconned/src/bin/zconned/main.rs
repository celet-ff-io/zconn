use clap::{
    Parser,
    builder::{
        Styles,
        styling::{AnsiColor, Effects},
    },
};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use miette::{IntoDiagnostic, Result};
use tap::Pipe as _;
use tokio::io::BufReader;

static STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Red.on_default());

/// zconned - to be built.
#[derive(Debug, Parser)]
#[command(version)]
#[command(styles = STYLES.clone())]
struct Args {
    #[command(flatten)]
    verbose: Verbosity<WarnLevel>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(args.verbose.log_level_filter().to_string()),
    )
    .init();

    let mut stdin = tokio::io::stdin().pipe(BufReader::new);
    let mut stdout = tokio::io::stdout();

    zconned::run(&mut stdin, &mut stdout)
        .await
        .into_diagnostic()?;
    Ok(())
}
