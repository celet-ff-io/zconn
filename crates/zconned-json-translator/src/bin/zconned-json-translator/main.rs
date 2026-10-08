use std::env;

use clap::{
    Parser,
    builder::{
        Styles,
        styling::{AnsiColor, Effects},
    },
};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use miette::{IntoDiagnostic, Result};
use tokio::io::{BufReader, BufWriter};

static STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Red.on_default());

/// zconned-json-translator - speaks JSON Lines to third-party clients and
/// length-delimited protobuf frames to the zconned core process.
///
/// Logs go to stderr only, so the JSON Lines stream stays clean.
#[derive(Debug, Parser)]
#[command(version)]
#[command(styles = STYLES.clone())]
struct Args {
    /// Path to the zconned core binary.
    ///
    /// Resolution order is this flag first, then the `ZCONNED__CORE`
    /// environment variable, then `"zconned"` looked up through `PATH`.
    #[arg(long, value_name = "PATH")]
    core: Option<String>,

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

    // Do NOT use clap's `env` attribute here: it cannot fall through to the
    // PATH default. Resolve the documented three-step chain manually.
    let core_bin = args
        .core
        .or_else(|| env::var("ZCONNED__CORE").ok())
        .unwrap_or_else(|| "zconned".to_owned());

    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = BufWriter::new(tokio::io::stdout());

    zconned_json_translator::run(&core_bin, &mut stdin, &mut stdout)
        .await
        .into_diagnostic()?;
    Ok(())
}
