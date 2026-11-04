//! Download periódico das blocklists e reconstrução do snapshot.
//!
//! Cada lista remota fica em `<data_dir>/blocklists/<nome>.txt`. No início o
//! snapshot é montado a partir desse cache, então o filtro funciona mesmo sem
//! rede. Downloads usam `If-None-Match` e só substituem o cache se o conteúdo
//! novo tiver ao menos uma entrada válida (descarta páginas de erro HTML).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use argus_core::config::{BlocklistConfig, BlocklistSource};
use reqwest::StatusCode;
use reqwest::header::{ETAG, IF_NONE_MATCH};
use tracing::{debug, info, warn};

use super::parse::parse;
use super::{Policy, Snapshot};
use crate::upstream::error_chain;

const MIN_SLEEP: Duration = Duration::from_secs(30);

pub struct Updater {
    policy: Arc<Policy>,
    http: reqwest::Client,
    cfg: BlocklistConfig,
    dir: PathBuf,
}

impl Updater {
    pub fn new(
        policy: Arc<Policy>,
        http: reqwest::Client,
        cfg: BlocklistConfig,
        dir: PathBuf,
    ) -> Self {
        Self {
            policy,
            http,
            cfg,
            dir,
        }
    }

    fn cache_file(&self, src: &BlocklistSource) -> PathBuf {
        match &src.path {
            Some(path) => path.clone(),
            None => self.dir.join(format!("{}.txt", src.name)),
        }
    }

    fn etag_file(&self, src: &BlocklistSource) -> PathBuf {
        self.dir.join(format!("{}.etag", src.name))
    }

    fn enabled(&self) -> impl Iterator<Item = &BlocklistSource> {
        self.cfg.sources.iter().filter(|s| s.enabled)
    }

    /// Lê todas as listas habilitadas do disco e troca o snapshot da política.
    pub async fn rebuild(&self) {
        let files: Vec<(BlocklistSource, PathBuf)> = self
            .enabled()
            .map(|s| (s.clone(), self.cache_file(s)))
            .collect();
        let snapshot = tokio::task::spawn_blocking(move || build_snapshot(&files)).await;
        match snapshot {
            Ok(snap) => {
                if snap.is_empty() {
                    warn!("nenhum domínio bloqueado carregado (listas ainda não baixadas?)");
                } else {
                    info!(domains = snap.len(), "blocklists ativas");
                }
                self.policy.replace(snap);
            }
            Err(e) => warn!(error = %e, "falha ao montar blocklists"),
        }
    }

    /// Laço de atualização; nunca retorna.
    pub async fn run(self) {
        if let Err(e) = tokio::fs::create_dir_all(&self.dir).await {
            warn!(dir = %self.dir.display(), error = %e, "não foi possível criar o diretório das blocklists");
        }
        let mut retry_at: HashMap<String, SystemTime> = HashMap::new();
        loop {
            let now = SystemTime::now();
            let mut changed = false;
            let remote: Vec<BlocklistSource> = self
                .enabled()
                .filter(|s| s.path.is_none())
                .cloned()
                .collect();
            for src in &remote {
                if self.due(src, &retry_at) > now {
                    continue;
                }
                match self.download(src).await {
                    Ok(updated) => {
                        retry_at.remove(&src.name);
                        changed |= updated;
                    }
                    Err(e) => {
                        warn!(list = %src.name, error = %e, retry_in = ?self.cfg.retry_interval, "falha ao atualizar blocklist");
                        retry_at.insert(src.name.clone(), now + self.cfg.retry_interval);
                    }
                }
            }
            if changed {
                self.rebuild().await;
            }
            let next = remote.iter().map(|s| self.due(s, &retry_at)).min();
            let sleep = next
                .and_then(|t| t.duration_since(SystemTime::now()).ok())
                .unwrap_or(self.cfg.update_interval)
                .max(MIN_SLEEP);
            debug!(?sleep, "próxima verificação de blocklists");
            tokio::time::sleep(sleep).await;
        }
    }

    /// Quando a lista precisa ser baixada: após uma falha, no horário de retry;
    /// senão, quando o cache em disco ficar mais velho que `update_interval`.
    fn due(&self, src: &BlocklistSource, retry_at: &HashMap<String, SystemTime>) -> SystemTime {
        if let Some(t) = retry_at.get(&src.name) {
            return *t;
        }
        std::fs::metadata(self.cache_file(src))
            .and_then(|m| m.modified())
            .map_or(SystemTime::UNIX_EPOCH, |mtime| {
                mtime + self.cfg.update_interval
            })
    }

    /// Tenta os espelhos em ordem. `Ok(true)` = conteúdo novo gravado.
    async fn download(&self, src: &BlocklistSource) -> Result<bool, String> {
        let mut last_err = String::from("nenhuma URL");
        for url in &src.urls {
            match self.fetch(src, url).await {
                Ok(updated) => return Ok(updated),
                Err(e) => {
                    debug!(list = %src.name, %url, error = %e, "espelho falhou");
                    last_err = format!("{url}: {e}");
                }
            }
        }
        Err(last_err)
    }

    async fn fetch(&self, src: &BlocklistSource, url: &str) -> Result<bool, String> {
        let cache = self.cache_file(src);
        let etag_path = self.etag_file(src);
        let mut req = self.http.get(url);
        if cache.exists()
            && let Ok(etag) = tokio::fs::read_to_string(&etag_path).await
        {
            req = req.header(IF_NONE_MATCH, etag.trim());
        }
        let mut resp = req.send().await.map_err(|e| error_chain(&e))?;

        if resp.status() == StatusCode::NOT_MODIFIED {
            touch(&cache).map_err(|e| e.to_string())?;
            debug!(list = %src.name, "blocklist sem alterações (304)");
            return Ok(false);
        }
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        let limit = self.cfg.max_download_mb.saturating_mul(1024 * 1024);
        if resp.content_length().is_some_and(|len| len > limit) {
            return Err(format!("maior que {} MiB", self.cfg.max_download_mb));
        }
        let etag = resp
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| error_chain(&e))? {
            if body.len() as u64 + chunk.len() as u64 > limit {
                return Err(format!("maior que {} MiB", self.cfg.max_download_mb));
            }
            body.extend_from_slice(&chunk);
        }

        let text = String::from_utf8_lossy(&body);
        let stats = parse(&text, src.format, |_| {});
        if stats.accepted == 0 {
            return Err("conteúdo sem nenhuma entrada válida (página de erro?)".into());
        }

        let tmp = cache.with_extension("txt.tmp");
        tokio::fs::write(&tmp, &body)
            .await
            .map_err(|e| e.to_string())?;
        tokio::fs::rename(&tmp, &cache)
            .await
            .map_err(|e| e.to_string())?;
        match etag {
            Some(tag) => tokio::fs::write(&etag_path, tag)
                .await
                .map_err(|e| e.to_string())?,
            None => {
                let _ = tokio::fs::remove_file(&etag_path).await;
            }
        }
        info!(list = %src.name, %url, entries = stats.accepted, bytes = body.len(), "blocklist atualizada");
        Ok(true)
    }
}

fn touch(path: &Path) -> std::io::Result<()> {
    std::fs::File::options()
        .write(true)
        .open(path)?
        .set_modified(SystemTime::now())
}

fn build_snapshot(files: &[(BlocklistSource, PathBuf)]) -> Snapshot {
    let mut builder = Snapshot::builder();
    for (src, path) in files {
        let text = match std::fs::read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(list = %src.name, path = %path.display(), "lista ainda não disponível em disco");
                continue;
            }
            Err(e) => {
                warn!(list = %src.name, path = %path.display(), error = %e, "falha ao ler blocklist");
                continue;
            }
        };
        let idx = builder.add_source(&src.name);
        let mut new = 0usize;
        let stats = parse(&text, src.format, |d| {
            new += usize::from(builder.insert(d, idx, src.match_subdomains))
        });
        info!(
            list = %src.name,
            entries = stats.accepted,
            unique = new,
            rejected = stats.rejected,
            "blocklist carregada"
        );
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::config::ListFormat;

    fn source(name: &str, format: ListFormat, subdomains: bool) -> BlocklistSource {
        BlocklistSource {
            name: name.into(),
            enabled: true,
            urls: vec![],
            path: None,
            format,
            match_subdomains: subdomains,
        }
    }

    #[test]
    fn merges_and_dedups_sources() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, "0.0.0.0 evil.com\n0.0.0.0 dup.com\n").unwrap();
        std::fs::write(&b, "dup.com\nexact.org\n").unwrap();
        let files = vec![
            (source("a", ListFormat::Hosts, true), a),
            (source("b", ListFormat::Domains, false), b),
            (
                source("missing", ListFormat::Domains, true),
                dir.path().join("nope.txt"),
            ),
        ];
        let snap = build_snapshot(&files);
        assert_eq!(snap.len(), 3);

        let policy = Policy::new([], []);
        policy.replace(snap);
        assert!(matches!(
            policy.check("www.evil.com"),
            super::super::Decision::Blocked { .. }
        ));
        assert!(matches!(
            policy.check("www.exact.org"),
            super::super::Decision::Pass
        ));
        match policy.check("dup.com") {
            super::super::Decision::Blocked { list, .. } => assert_eq!(list, "a"),
            other => panic!("{other:?}"),
        }
    }
}
