use std::io;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use tl::collection::provider::CollectionProvider;
use tl::collection::velociraptor::VelociraptorProvider;
use tl::parsers::mft_parser;
use tl::parsers::usn_parser;
use tl::timeline::store::TimelineStore;
use tl::tui::app::App;

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

    /// Export timeline in bodyfile (mactime) format
    #[arg(long)]
    export_bodyfile: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    // Step 1: Open the collection
    let provider = VelociraptorProvider::open(&cli.collection)
        .with_context(|| format!("Failed to open collection: {}", cli.collection.display()))?;

    // Step 2: Discover artifacts
    let manifest = provider.discover();
    let meta = provider.metadata();

    // Print artifact discovery summary to stderr (so it doesn't interfere with TUI)
    eprintln!(
        "Collection: {} ({})",
        meta.hostname, meta.collection_timestamp
    );
    eprintln!("Source tool: {}", meta.source_tool);
    eprintln!(
        "Artifacts found: {} total files",
        manifest.all_paths.len()
    );
    if manifest.has_mft() {
        eprintln!("  $MFT: found");
    }
    if manifest.has_usnjrnl() {
        eprintln!("  $UsnJrnl: found");
    }
    eprintln!(
        "  Event logs: {}, Prefetch: {}, LNK: {}, Registry hives: {}",
        manifest.event_logs().len(),
        manifest.prefetch_files().len(),
        manifest.lnk_files().len(),
        manifest.registry_hives().len(),
    );

    // Step 3: Parse $MFT into TimelineStore
    let mut store = TimelineStore::new();

    if let Some(ref mft_path) = manifest.mft {
        eprintln!("Parsing $MFT...");
        let mft_data = provider
            .open_file(mft_path)
            .context("Failed to read $MFT from collection")?;
        mft_parser::parse_mft(&mft_data, &mut store)
            .context("Failed to parse $MFT")?;
        eprintln!("  {} timeline entries from $MFT", store.len());
    } else {
        eprintln!("Warning: No $MFT found in collection");
    }

    // Step 3b: Parse $UsnJrnl:$J into TimelineStore
    if let Some(ref usn_path) = manifest.usnjrnl_j {
        eprintln!("Parsing $UsnJrnl:$J...");
        let usn_data = provider
            .open_file(usn_path)
            .context("Failed to read $UsnJrnl:$J from collection")?;
        eprintln!("  $UsnJrnl size: {} bytes", usn_data.len());
        let records = usn_parser::parse_usn_journal(&usn_data)
            .context("Failed to parse $UsnJrnl:$J")?;
        eprintln!("  {} USN records parsed", records.len());
        usn_parser::merge_usn_to_timeline(&records, &mut store);
        eprintln!("  Timeline now has {} entries", store.len());
    }
    // Parse execution evidence
    eprintln!("Parsing execution evidence...");
    tl::parsers::prefetch_parser::parse_prefetch_files(&provider, &manifest, &mut store)?;
    tl::parsers::amcache_parser::parse_amcache(&provider, &manifest, &mut store)?;
    tl::parsers::shimcache_parser::parse_shimcache(&provider, &manifest, &mut store)?;
    tl::parsers::bam_parser::parse_bam(&provider, &manifest, &mut store)?;
    tl::parsers::services_parser::parse_services(&provider, &manifest, &mut store)?;
    eprintln!("  Timeline now has {} entries", store.len());

    // Parse SRUM
    eprintln!("Parsing SRUM...");
    tl::parsers::srum_parser::parse_srum(&provider, &manifest, &mut store)?;
    eprintln!("  Timeline now has {} entries", store.len());

    // Parse persistence/autorun artifacts
    eprintln!("Parsing persistence artifacts...");
    tl::parsers::autorun_parser::parse_autoruns(&provider, &manifest, &mut store)?;
    tl::parsers::wmi_parser::parse_wmi_persistence(&provider, &manifest, &mut store)?;
    eprintln!("  Timeline now has {} entries", store.len());

    // Parse user activity artifacts
    eprintln!("Parsing user activity artifacts...");
    tl::parsers::lnk_parser::parse_lnk_files(&provider, &manifest, &mut store)?;
    tl::parsers::jumplist_parser::parse_jump_lists(&provider, &manifest, &mut store)?;
    tl::parsers::userassist_parser::parse_userassist(&provider, &manifest, &mut store)?;
    tl::parsers::shellbag_parser::parse_shellbags(&provider, &manifest, &mut store)?;
    tl::parsers::recycle_bin_parser::parse_recycle_bin(&provider, &manifest, &mut store)?;
    tl::parsers::mru_parser::parse_mru_lists(&provider, &manifest, &mut store)?;
    eprintln!("  Timeline now has {} entries", store.len());

    // Parse event logs
    eprintln!("Parsing event logs...");
    tl::parsers::evtx_parser::parse_event_logs(&provider, &manifest, &mut store)?;
    tl::parsers::schtask_parser::parse_scheduled_tasks(&provider, &manifest, &mut store)?;
    eprintln!("  Timeline now has {} entries", store.len());

    store.sort();

    // Step 4: Handle export modes
    if let Some(ref csv_path) = cli.export_csv {
        let file = std::fs::File::create(csv_path)?;
        let mut writer = std::io::BufWriter::new(file);
        tl::export::csv_export::export_csv(&store, &mut writer)?;
        eprintln!("Exported {} entries to {}", store.len(), csv_path.display());
        return Ok(());
    }
    if let Some(ref json_path) = cli.export_json {
        let file = std::fs::File::create(json_path)?;
        let mut writer = std::io::BufWriter::new(file);
        tl::export::json_export::export_json(&store, &mut writer)?;
        eprintln!("Exported {} entries to {}", store.len(), json_path.display());
        return Ok(());
    }
    if let Some(ref bodyfile_path) = cli.export_bodyfile {
        let file = std::fs::File::create(bodyfile_path)?;
        let mut writer = std::io::BufWriter::new(file);
        tl::export::bodyfile_export::export_bodyfile(&store, &mut writer)?;
        eprintln!("Exported {} entries to {}", store.len(), bodyfile_path.display());
        return Ok(());
    }

    // Step 5: Launch TUI
    run_tui(store, meta.hostname, meta.collection_timestamp)?;

    Ok(())
}

fn run_tui(store: TimelineStore, hostname: String, date: String) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(store, hostname, date);

    loop {
        terminal.draw(|f| {
            // Calculate visible rows based on terminal height, minus header(3) + status(1) + table header(1) + margins
            app.visible_rows = f.area().height.saturating_sub(6) as usize;
            tl::tui::timeline_view::render(f, &app);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                tl::tui::keybindings::handle_key(&mut app, key);
            }
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
