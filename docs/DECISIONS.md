# Decisões técnicas

Registro curto das decisões e do motivo de cada uma. Uma decisão nova que
substitui outra a referencia em vez de apagá-la.

## D-001 — GPL-2.0-only

A libclamav é GPLv2. Como o scanner se liga a ela, o projeto inteiro é
GPL-2.0-only. Consequência: dependências precisam ser compatíveis com a GPLv2
(MIT, BSD, ISC, Zlib, Unicode, MPL-2.0 ou duplas com uma dessas). **Apache-2.0
sozinha não é compatível com a GPLv2.**

## D-002 — `hickory-proto` para o formato wire, servidor próprio

O `hickory-proto` (do projeto Hickory DNS) faz parse e serialização das
mensagens. Os laços UDP/TCP, a política, o cache e o fallback de upstream são
próprios, porque:

- no Windows, um ICMP "port unreachable" de um envio anterior chega como
  `WSAECONNRESET` no próximo `recv_from` do socket UDP; o laço precisa ignorar
  esse erro em vez de morrer;
- cada decisão (bloqueio, allowlist, cache, upstream) precisa de log e evento
  num ponto único e explícito;
- a API do `hickory-server` muda bastante entre versões; a do `hickory-proto` é estável.

## D-003 — DoH com IPs de bootstrap, sem DNS do sistema

O Argus é o DNS do sistema; resolver o próprio upstream pelo sistema seria
circular. Cada servidor DoH tem `bootstrap` obrigatório quando a URL usa nome.
O cliente DoH recusa qualquer outro nome. Os downloads de listas resolvem
direto pelos upstreams (`http::PoolResolver`).

## D-004 — Upstreams padrão: Quad9 e Cloudflare *security*

Os dois também filtram malware, uma camada a mais. Ordem = preferência. Uma
falha de transporte (rede, TLS, HTTP ≠ 200, resposta que não confere com a
pergunta) passa para o próximo, e o servidor que falhou vai para o fim da fila
por `failure_backoff`. SERVFAIL vindo do upstream é resposta válida, não falha:
pode ser uma falha legítima de validação DNSSEC, e repetir em outro servidor
contornaria essa validação.

## D-005 — Fontes de blocklist

Verificadas em 2026-11-04:

| Fonte | Formato | Termos | Padrão |
|-------|---------|--------|--------|
| URLhaus `downloads/hostfile` | — | **descontinuado (HTTP 410)** | — |
| urlhaus-filter (malware-filter), derivado do URLhaus | hosts | CC0 / MIT. Remove domínios populares (Tranco, Umbrella, Cloudflare Radar) | ligado |
| phishing-filter (malware-filter): OpenPhish, PhishTank, IPThreat | hosts | CC BY-SA 4.0 | ligado |
| Phishing Army | domains | gratuito para uso pessoal/individual; política declarada de poucos falsos positivos | ligado |
| OpenPhish Community Feed | urls | **somente uso pessoal, sem redistribuição** | desligado |

O OpenPhish fica desligado porque um projeto distribuído não pode aceitar os
termos em nome de quem o usa. Além disso, o feed traz URLs, e o host de uma URL
de phishing às vezes é uma plataforma compartilhada; por isso a fonte vem com
`match_subdomains = false`.

Os malware-filter têm três espelhos (GitLab Pages, GitHub Pages, Cloudflare
Pages), tentados em ordem.

## D-006 — Estrutura do lookup

`HashMap<Box<str>, Entry>` por domínio. A consulta testa o nome e cada sufixo
(`a.b.c`, `b.c`, `c`): no máximo ~5 acessos ao hash para nomes comuns. Com ~150
mil domínios o conjunto ocupa poucas dezenas de MB. Uma trie economizaria
memória, mas complica sem ganho mensurável neste volume. O snapshot é imutável
e trocado via `ArcSwap`: consultas nunca esperam uma atualização.

Proteções contra falso positivo e lista corrompida:

- entradas sem ponto (TLDs), IPs e nomes de loopback são descartadas no parse;
- um download só substitui o cache se tiver ao menos uma entrada válida
  (páginas HTML de erro são rejeitadas);
- hosts de infraestrutura (upstreams, fontes de listas) nunca são bloqueados;
- o log de bloqueio sempre diz qual lista e qual entrada casou.

## D-007 — TLS: `native-tls` (SChannel), não rustls

O padrão do `reqwest` 0.13 é rustls com aws-lc-rs; a alternativa é ring. Os
dois trazem licenças incompatíveis com a GPLv2 (Apache-2.0 e a licença
OpenSSL). O SChannel é biblioteca do sistema (coberta pela exceção de
bibliotecas de sistema da GPL) e usa o repositório de certificados do Windows.

**Pendência:** o `reqwest` ainda depende do `sync_wrapper` (só Apache-2.0).
Para distribuir binários sem conflito de licença, a recomendação é trocar o
`reqwest` por `hyper-util` (cliente legado) + `hyper-tls`, usados
diretamente. O uso pessoal (sem distribuição) não é afetado.

## D-008 — Resposta padrão para bloqueio: `0.0.0.0` / `::`

Com NXDOMAIN, alguns clientes tentam sufixos de busca ou outros resolvers. Um
endereço nulo faz a conexão falhar na hora. Para outros tipos (HTTPS, MX,
TXT...), a resposta é NOERROR sem registros. NXDOMAIN segue disponível em
`blocked_response`.

## D-009 — Detalhes de protocolo

- EDNS: anunciamos 1232 bytes (DNS Flag Day 2020); respostas UDP maiores
  que o limite do cliente saem truncadas (TC=1) e o cliente repete por TCP.
- Cache: TTL = menor TTL da resposta. Negativas usam `min(TTL do SOA,
  SOA.minimum)` (RFC 2308), limitadas por `negative_max_ttl`. Sem SOA, ou com
  SERVFAIL ou TC, a resposta não entra no cache.
- O cache é consultado depois da política: mudar as listas vale na hora,
  inclusive para nomes já em cache. Alvos de CNAME são rechecados a cada resposta.
- Nomes sem ponto recebem NXDOMAIN local (não vazam para o upstream).
  `localhost` resolve para loopback (RFC 6761). `use-application-dns.net`
  recebe NXDOMAIN para desligar o DoH automático do Firefox.

## D-010 — Configuração

TOML com `deny_unknown_fields`: erro de digitação é erro, não um padrão
silencioso. Definir `[[dns.blocklists.sources]]` substitui a lista padrão
inteira, para o usuário ter controle total. Só HTTPS é aceito para upstreams e
blocklists.
