use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{LogConfig, LogFormat};

/// Mantém vivo o writer assíncrono do arquivo de log. Descartar = perder logs pendentes.
pub struct LogGuard {
    _file: Option<WorkerGuard>,
}

/// Inicializa o `tracing` global.
///
/// - Console: formato `pretty`/`compact` (humano) ou `json`.
/// - Arquivo (opcional): sempre JSON, uma linha por evento, rotação diária.
///
/// `RUST_LOG`, se definida, tem prioridade sobre `log.level`.
pub fn init(cfg: &LogConfig) -> Result<LogGuard, String> {
    let filter = || {
        EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new(&cfg.level))
            .map_err(|e| format!("log.level inválido ({:?}): {e}", cfg.level))
    };

    let console = match cfg.format {
        LogFormat::Pretty => tracing_subscriber::fmt::layer()
            .with_target(true)
            .compact()
            .with_filter(filter()?)
            .boxed(),
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_filter(filter()?)
            .boxed(),
    };

    let (file_layer, guard) = match &cfg.file {
        Some(path) => {
            let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
            let dir = dir.unwrap_or_else(|| std::path::Path::new("."));
            let prefix = path
                .file_name()
                .ok_or_else(|| format!("log.file inválido: {}", path.display()))?;
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("não foi possível criar {}: {e}", dir.display()))?;
            let appender = tracing_appender::rolling::daily(dir, prefix);
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(false)
                .with_ansi(false)
                .with_writer(writer)
                .with_filter(filter()?)
                .boxed();
            (Some(layer), Some(guard))
        }
        None => (None, None),
    };

    tracing_subscriber::registry()
        .with(console)
        .with(file_layer)
        .try_init()
        .map_err(|e| format!("falha ao inicializar logs: {e}"))?;

    Ok(LogGuard { _file: guard })
}
