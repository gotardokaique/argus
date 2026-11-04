//! Parsers dos formatos de blocklist. Entrada não confiável: nada aqui entra
//! em pânico, linhas inválidas são apenas contadas.

use std::net::IpAddr;

use argus_core::config::ListFormat;

use crate::domain::normalize_entry;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ParseStats {
    pub accepted: usize,
    pub rejected: usize,
}

/// Faz o parse de `text` e chama `sink` para cada domínio normalizado.
pub fn parse(text: &str, format: ListFormat, mut sink: impl FnMut(&str)) -> ParseStats {
    let mut stats = ParseStats::default();
    let mut emit = |candidate: &str, stats: &mut ParseStats| match normalize_entry(candidate) {
        Some(d) => {
            stats.accepted += 1;
            sink(&d);
        }
        None => stats.rejected += 1,
    };

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        match format {
            ListFormat::Hosts => {
                let line = strip_inline_comment(line);
                let mut tokens = line.split_whitespace();
                match tokens.next().map(str::parse::<IpAddr>) {
                    Some(Ok(_)) => tokens.for_each(|t| emit(t, &mut stats)),
                    _ => stats.rejected += 1,
                }
            }
            ListFormat::Domains => {
                let token = strip_inline_comment(line)
                    .split_whitespace()
                    .next()
                    .unwrap_or("");
                let token = token.strip_prefix("||").unwrap_or(token);
                let token = token.strip_suffix('^').unwrap_or(token);
                emit(token, &mut stats);
            }
            ListFormat::Urls => match url_host(line) {
                Some(host) => emit(&host, &mut stats),
                None => stats.rejected += 1,
            },
        }
    }
    stats
}

fn strip_inline_comment(line: &str) -> &str {
    line.split_once('#')
        .map_or(line, |(before, _)| before)
        .trim()
}

/// Extrai o host de uma URL; URLs cujo host é um IP são ignoradas.
fn url_host(line: &str) -> Option<String> {
    let parsed = url::Url::parse(line)
        .or_else(|_| url::Url::parse(&format!("http://{line}")))
        .ok()?;
    match parsed.host()? {
        url::Host::Domain(d) => Some(d.to_owned()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(text: &str, format: ListFormat) -> (Vec<String>, ParseStats) {
        let mut out = Vec::new();
        let stats = parse(text, format, |d| out.push(d.to_owned()));
        (out, stats)
    }

    #[test]
    fn hosts_format() {
        let text = "# comentário\n\
                    127.0.0.1 localhost\n\
                    0.0.0.0 0.0.0.0\n\
                    0.0.0.0 Evil.com  # inline\n\
                    0.0.0.0\tfoo.net bar.org\n\
                    :: v6.example\n\
                    sem-ip.com\n\
                    \n";
        let (d, s) = collect(text, ListFormat::Hosts);
        assert_eq!(d, ["evil.com", "foo.net", "bar.org", "v6.example"]);
        assert_eq!(s.rejected, 3); // localhost, 0.0.0.0, linha sem IP
    }

    #[test]
    fn domains_format() {
        let text =
            "! adblock\n# c\nphish.example\n||ads.example^\n*.wild.example\nfoo.example # x\ncom\n";
        let (d, s) = collect(text, ListFormat::Domains);
        assert_eq!(
            d,
            [
                "phish.example",
                "ads.example",
                "wild.example",
                "foo.example"
            ]
        );
        assert_eq!(s.rejected, 1);
    }

    #[test]
    fn urls_format() {
        let text = "http://whatsapp.nlabstech.in/\n\
                    https://domipa.s3.us-east-1.amazonaws.com/NuEw.html#elel8@x.org\n\
                    https://login.EXAMPLE.pw/a%23b/\n\
                    http://203.0.113.9/login\n\
                    sem-esquema.example/path\n\
                    lixo:::\n";
        let (d, s) = collect(text, ListFormat::Urls);
        assert_eq!(
            d,
            [
                "whatsapp.nlabstech.in",
                "domipa.s3.us-east-1.amazonaws.com",
                "login.example.pw",
                "sem-esquema.example"
            ]
        );
        assert_eq!(s.rejected, 2);
    }

    #[test]
    fn html_error_page_yields_nothing_useful() {
        let html = "<!DOCTYPE HTML>\n<html><head><title>410 Gone</title></head></html>\n";
        let (d, _) = collect(html, ListFormat::Hosts);
        assert!(d.is_empty());
    }
}
