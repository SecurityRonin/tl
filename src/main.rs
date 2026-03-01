use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "tl", about = "Rapid forensic triage timeline")]
struct Cli {
    /// Path to collection (zip file or directory)
    collection: std::path::PathBuf,

    /// Export timeline to CSV instead of opening TUI
    #[arg(long)]
    export_csv: Option<std::path::PathBuf>,

    /// Export timeline to JSON instead of opening TUI
    #[arg(long)]
    export_json: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    println!("Opening collection: {}", cli.collection.display());
    Ok(())
}
