//! `argus-dns`: filtro DNS como binário de console (Fase 1).

use std::path::PathBuf;
use std::process::ExitCode;

use argus_core::config::Config;
use argus_dns::DnsService;
use clap::Parser;
use tracing::{error, info};

#[derive(Parser)]
#[command(version, about = "Filtro DNS local do Argus")]
struct Args {
    /// Arquivo de configuração TOML. Padrão: ./argus.toml, se existir.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Apenas valida a configuração e sai.
    #[arg(long)]
    check: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let cfg = match load_config(args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("erro: {e}");
            return ExitCode::FAILURE;
        }
    };
    if args.check {
        println!("configuração válida");
        return ExitCode::SUCCESS;
    }

    let _log = match argus_core::logging::init(&cfg.log) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("erro: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "falha ao criar o runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn load_config(path: Option<PathBuf>) -> Result<Config, String> {
    let path = path.or_else(|| Some(PathBuf::from("argus.toml")).filter(|p| p.exists()));
    match path {
        Some(p) => Config::load(&p).map_err(|e| e.to_string()),
        None => Ok(Config::default()),
    }
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    info!(data_dir = %cfg.data_dir.display(), "iniciando argus-dns {}", env!("CARGO_PKG_VERSION"));
    let mut service = DnsService::start(&cfg).await?;
    info!("pronto. Ctrl+C para encerrar");
    tokio::select! {
        result = service.wait() => result?,
        _ = tokio::signal::ctrl_c() => info!("encerrando"),
    }
    service.shutdown().await;
    Ok(())
}
