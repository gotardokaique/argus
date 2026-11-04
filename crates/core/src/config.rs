//! Configuração do Argus (TOML).
//!
//! Todos os campos têm valores padrão: um arquivo vazio é uma configuração
//! válida. Caminhos relativos são resolvidos a partir do diretório do arquivo.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("não foi possível ler {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("TOML inválido: {0}")]
    Parse(String),
    #[error("configuração inválida: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Diretório de dados (cache de blocklists; futuramente quarentena e assinaturas).
    pub data_dir: PathBuf,
    pub log: LogConfig,
    pub dns: DnsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            log: LogConfig::default(),
            dns: DnsConfig::default(),
        }
    }
}

/// `%ProgramData%\Argus` no Windows; `./argus-data` nos demais sistemas.
fn default_data_dir() -> PathBuf {
    match std::env::var_os("ProgramData") {
        Some(dir) if cfg!(windows) => PathBuf::from(dir).join("Argus"),
        _ => PathBuf::from("argus-data"),
    }
}

impl Config {
    /// Lê, valida e resolve caminhos relativos a partir do diretório do arquivo.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        let mut cfg: Config = toml::from_str(&text)
            .map_err(|e| ConfigError::Parse(format!("{}: {e}", path.display())))?;
        let base = path.parent().unwrap_or(Path::new("."));
        cfg.resolve_paths(base);
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn resolve_paths(&mut self, base: &Path) {
        let fix = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        fix(&mut self.data_dir);
        if let Some(file) = &mut self.log.file {
            fix(file);
        }
        for src in &mut self.dns.blocklists.sources {
            if let Some(path) = &mut src.path {
                fix(path);
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.dns.validate().map_err(ConfigError::Invalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// Filtro no formato do `tracing` (ex.: `info`, `info,argus_dns=debug`).
    pub level: String,
    pub format: LogFormat,
    /// Arquivo de log em JSON (uma linha por evento, rotação diária).
    pub file: Option<PathBuf>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: LogFormat::Pretty,
            file: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    /// Endereços de escuta (UDP e TCP em cada um).
    pub listen: Vec<SocketAddr>,
    pub blocked_response: BlockedResponse,
    /// TTL (segundos) das respostas para domínios bloqueados.
    pub blocked_ttl: u32,
    /// Tempo máximo para responder uma consulta; estourado, o cliente recebe SERVFAIL.
    #[serde(with = "humantime_serde")]
    pub query_timeout: Duration,
    /// Consultas simultâneas em processamento; acima disso, pacotes UDP são descartados.
    pub max_concurrent_queries: usize,
    /// Encaminhar nomes sem ponto (ex.: `impressora`) ao upstream. Padrão: NXDOMAIN local.
    pub forward_single_label: bool,
    /// Domínios sempre liberados (incluindo subdomínios). Prioridade sobre as blocklists.
    pub allowlist: Vec<String>,
    pub upstream: UpstreamConfig,
    pub cache: CacheConfig,
    pub blocklists: BlocklistConfig,
    /// Zonas locais encaminhadas a servidores DNS comuns (ex.: `lan` → roteador).
    pub forward_zones: Vec<ForwardZone>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen: vec![
                SocketAddr::from(([127, 0, 0, 1], 53)),
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 53)),
            ],
            blocked_response: BlockedResponse::NullIp,
            blocked_ttl: 60,
            query_timeout: Duration::from_secs(5),
            max_concurrent_queries: 1024,
            forward_single_label: false,
            allowlist: Vec::new(),
            upstream: UpstreamConfig::default(),
            cache: CacheConfig::default(),
            blocklists: BlocklistConfig::default(),
            forward_zones: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedResponse {
    /// A → 0.0.0.0, AAAA → ::, demais tipos → NOERROR sem respostas.
    NullIp,
    /// NXDOMAIN para qualquer tipo.
    Nxdomain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Tempo máximo por tentativa em um servidor antes de passar ao próximo.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Após uma falha, o servidor vai para o fim da fila por este período.
    #[serde(with = "humantime_serde")]
    pub failure_backoff: Duration,
    /// Servidores DoH em ordem de preferência.
    pub servers: Vec<DohServer>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            failure_backoff: Duration::from_secs(30),
            servers: vec![
                DohServer {
                    name: "quad9".into(),
                    url: "https://dns.quad9.net/dns-query".into(),
                    bootstrap: ips(&["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"]),
                },
                DohServer {
                    name: "cloudflare-security".into(),
                    url: "https://security.cloudflare-dns.com/dns-query".into(),
                    bootstrap: ips(&[
                        "1.1.1.2",
                        "1.0.0.2",
                        "2606:4700:4700::1112",
                        "2606:4700:4700::1002",
                    ]),
                },
            ],
        }
    }
}

fn ips(list: &[&str]) -> Vec<IpAddr> {
    list.iter()
        .map(|s| s.parse().expect("IP padrão válido"))
        .collect()
}

/// Servidor DNS-over-HTTPS (RFC 8484).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DohServer {
    pub name: String,
    pub url: String,
    /// IPs do servidor. Obrigatório quando a URL usa nome: como o Argus é o DNS do
    /// sistema, resolver o próprio upstream pelo sistema seria circular.
    #[serde(default)]
    pub bootstrap: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
    /// Limites aplicados ao TTL das respostas positivas (segundos).
    pub min_ttl: u32,
    pub max_ttl: u32,
    /// Limite do TTL de respostas negativas (NXDOMAIN/NODATA), RFC 2308.
    pub negative_max_ttl: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 10_000,
            min_ttl: 0,
            max_ttl: 86_400,
            negative_max_ttl: 3_600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlocklistConfig {
    /// Idade máxima do cache local de uma lista antes de baixá-la de novo.
    #[serde(with = "humantime_serde")]
    pub update_interval: Duration,
    /// Espera antes de tentar de novo após falha de download.
    #[serde(with = "humantime_serde")]
    pub retry_interval: Duration,
    /// Tamanho máximo aceito por download, em MiB.
    pub max_download_mb: u64,
    /// Definir `sources` no TOML substitui a lista padrão inteira.
    pub sources: Vec<BlocklistSource>,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        let mf = |file: &str| {
            vec![
                format!("https://malware-filter.gitlab.io/malware-filter/{file}"),
                format!("https://curbengh.github.io/malware-filter/{file}"),
                format!("https://malware-filter.pages.dev/{file}"),
            ]
        };
        Self {
            update_interval: Duration::from_secs(6 * 3600),
            retry_interval: Duration::from_secs(15 * 60),
            max_download_mb: 64,
            sources: vec![
                BlocklistSource {
                    name: "urlhaus-filter".into(),
                    enabled: true,
                    urls: mf("urlhaus-filter-hosts.txt"),
                    path: None,
                    format: ListFormat::Hosts,
                    match_subdomains: true,
                },
                BlocklistSource {
                    name: "phishing-filter".into(),
                    enabled: true,
                    urls: mf("phishing-filter-hosts.txt"),
                    path: None,
                    format: ListFormat::Hosts,
                    match_subdomains: true,
                },
                BlocklistSource {
                    name: "phishing-army".into(),
                    enabled: true,
                    urls: vec!["https://phishing.army/download/phishing_army_blocklist.txt".into()],
                    path: None,
                    format: ListFormat::Domains,
                    match_subdomains: true,
                },
                // Termos do OpenPhish: somente uso pessoal, sem redistribuição.
                // Desligada por padrão; quem habilita aceita os termos.
                BlocklistSource {
                    name: "openphish".into(),
                    enabled: false,
                    urls: vec!["https://openphish.com/feed.txt".into()],
                    path: None,
                    format: ListFormat::Urls,
                    match_subdomains: false,
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistSource {
    /// Identificador; também nomeia o arquivo de cache (`[A-Za-z0-9_-]`).
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// URLs HTTPS (espelhos), tentadas em ordem. Exclusivo com `path`.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Arquivo local. Exclusivo com `urls`.
    #[serde(default)]
    pub path: Option<PathBuf>,
    pub format: ListFormat,
    /// Bloquear também os subdomínios de cada entrada.
    #[serde(default = "yes")]
    pub match_subdomains: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListFormat {
    /// `0.0.0.0 dominio [dominio...]`
    Hosts,
    /// Um domínio por linha (aceita também `||dominio^`).
    Domains,
    /// Uma URL por linha; usa-se o host.
    Urls,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardZone {
    /// Zona (ex.: `lan`, `home.arpa`, `168.192.in-addr.arpa`).
    pub zone: String,
    /// Servidores DNS comuns (UDP, com fallback para TCP em respostas truncadas).
    pub servers: Vec<SocketAddr>,
}

impl DnsConfig {
    fn validate(&self) -> Result<(), String> {
        if self.listen.is_empty() {
            return Err("dns.listen está vazio".into());
        }
        if self.query_timeout.is_zero() || self.upstream.timeout.is_zero() {
            return Err("timeouts do DNS precisam ser maiores que zero".into());
        }
        if self.max_concurrent_queries == 0 {
            return Err("dns.max_concurrent_queries precisa ser maior que zero".into());
        }
        if self.blocked_ttl > 86_400 {
            return Err("dns.blocked_ttl acima de 86400".into());
        }
        if self.cache.min_ttl > self.cache.max_ttl {
            return Err("dns.cache.min_ttl maior que dns.cache.max_ttl".into());
        }

        if self.upstream.servers.is_empty() {
            return Err("nenhum servidor em dns.upstream.servers".into());
        }
        let mut names = HashSet::new();
        for s in &self.upstream.servers {
            if s.name.is_empty() || !names.insert(s.name.as_str()) {
                return Err(format!("nome de upstream vazio ou repetido: {:?}", s.name));
            }
            let url = url::Url::parse(&s.url)
                .map_err(|e| format!("upstream {}: URL inválida: {e}", s.name))?;
            if url.scheme() != "https" {
                return Err(format!("upstream {}: apenas https é aceito", s.name));
            }
            match url.host() {
                Some(url::Host::Domain(_)) if s.bootstrap.is_empty() => {
                    return Err(format!(
                        "upstream {}: `bootstrap` é obrigatório quando a URL usa nome de host",
                        s.name
                    ));
                }
                None => return Err(format!("upstream {}: URL sem host", s.name)),
                _ => {}
            }
        }

        let mut names = HashSet::new();
        for src in &self.blocklists.sources {
            let valid_name = !src.name.is_empty()
                && src
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            if !valid_name || !names.insert(src.name.as_str()) {
                return Err(format!(
                    "nome de blocklist inválido ou repetido: {:?}",
                    src.name
                ));
            }
            match (src.urls.is_empty(), &src.path) {
                (true, None) => {
                    return Err(format!("blocklist {}: defina `urls` ou `path`", src.name));
                }
                (false, Some(_)) => {
                    return Err(format!(
                        "blocklist {}: `urls` e `path` são exclusivos",
                        src.name
                    ));
                }
                _ => {}
            }
            for u in &src.urls {
                let url = url::Url::parse(u)
                    .map_err(|e| format!("blocklist {}: URL inválida {u}: {e}", src.name))?;
                if url.scheme() != "https" {
                    return Err(format!(
                        "blocklist {}: apenas https é aceito ({u})",
                        src.name
                    ));
                }
            }
        }
        if self.blocklists.max_download_mb == 0 {
            return Err("dns.blocklists.max_download_mb precisa ser maior que zero".into());
        }

        for z in &self.forward_zones {
            if z.zone.trim_matches('.').is_empty() || z.servers.is_empty() {
                return Err(format!(
                    "forward_zones: zona {:?} sem nome ou sem servidores",
                    z.zone
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_uses_defaults() {
        let cfg = Config::from_toml_str("").unwrap();
        assert_eq!(cfg.dns.listen.len(), 2);
        assert_eq!(cfg.dns.upstream.servers[0].name, "quad9");
        assert!(
            cfg.dns
                .blocklists
                .sources
                .iter()
                .any(|s| s.name == "openphish" && !s.enabled)
        );
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../../../config/argus.example.toml");
        let cfg = Config::from_toml_str(text).unwrap();
        assert_eq!(cfg.dns.blocked_response, BlockedResponse::NullIp);
    }

    #[test]
    fn partial_section_keeps_other_defaults() {
        let cfg = Config::from_toml_str("[dns.upstream]\ntimeout = \"2s\"\n").unwrap();
        assert_eq!(cfg.dns.upstream.timeout, Duration::from_secs(2));
        assert_eq!(cfg.dns.upstream.servers.len(), 2);
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Config::from_toml_str("[dns]\nlisten_typo = []\n").is_err());
    }

    #[test]
    fn rejects_doh_without_bootstrap() {
        let toml = r#"
            [[dns.upstream.servers]]
            name = "x"
            url = "https://dns.example/dns-query"
        "#;
        let err = Config::from_toml_str(toml).unwrap_err().to_string();
        assert!(err.contains("bootstrap"), "{err}");
    }

    #[test]
    fn rejects_plain_http_blocklist() {
        let toml = r#"
            [[dns.blocklists.sources]]
            name = "x"
            urls = ["http://example.com/list.txt"]
            format = "domains"
        "#;
        assert!(Config::from_toml_str(toml).is_err());
    }
}
