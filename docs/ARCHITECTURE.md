# Arquitetura

## Visão geral

```
                         ┌──────────────────────────── user-mode ─────────────────────────────┐
                         │                                                                     │
   ┌────────────┐  named │  ┌──────────────────────────── argus-service ───────────────────┐   │
   │  UI Tauri  │◄─pipe─►│  │ (Windows Service, LocalSystem)                               │   │
   └────────────┘        │  │                                                              │   │
   ┌────────────┐  named │  │  política · allowlist · quarentena · logs · atualizações     │   │
   │ argus (CLI)│◄─pipe─►│  │                                                              │   │
   └────────────┘        │  │   ┌──────────────┐   ┌──────────────────┐                    │   │
                         │  │   │  DNS filter  │   │ fila de vereditos │                    │   │
   apps ──DNS 127.0.0.1──┼──┼──►│ (argus-dns)  │   └────────┬─────────┘                    │   │
                         │  │   └──────┬───────┘            │ IPC                          │   │
                         │  └──────────┼────────────────────┼──────────────────────────────┘   │
                         │             │ DoH (HTTPS)        ▼                                  │
                         │             ▼            ┌──────────────────┐                       │
                         │      Quad9 / Cloudflare  │ argus-scan-worker│ baixo privilégio      │
                         │                          │ libclamav, YARA-X│ (AppContainer /       │
                         │                          │ goblin, hashes   │  token restrito)      │
                         │                          └──────────────────┘                       │
                         └──────────────────────────────▲──────────────────────────────────────┘
                                                        │ FilterConnectCommunicationPort
                         ┌──────────────────────────────┴──────────────────────────────────────┐
                         │ kernel: argus.sys (minifilter)  IRP_MJ_CREATE / seção de imagem       │
                         │ intercepta → pergunta → aplica (timeout → fail-open)                 │
                         └─────────────────────────────────────────────────────────────────────┘
```

## Componentes

| Caminho | Papel | Linguagem |
|---------|-------|-----------|
| `driver/` | Minifilter: intercepta criação/execução de arquivos, envia ao serviço e aplica a resposta. Nenhuma decisão própria. | C (WDK) |
| `crates/core` | Tipos compartilhados: `Config` (TOML), `Verdict`, `Event`, inicialização de logs. Sem I/O de rede. | Rust |
| `crates/dns` | Filtro DNS local. Biblioteca (`DnsService`) e binário de console `argus-dns`. | Rust |
| `crates/scanner` | Motores de detecção. Roda dentro do worker isolado. | Rust (+ libclamav via FFI) |
| `crates/service` | Orquestrador: hospeda o DNS, gerencia workers, conversa com o driver e com a UI. | Rust |
| `crates/cli` | Interface de linha de comando (scan sob demanda, quarentena, status). | Rust |
| `ui/` | Interface desktop. | Tauri + React/TS + shadcn/ui |
| `rules/` | Regras YARA próprias. | YARA |

## Fronteiras de confiança

1. **Kernel ↔ serviço.** O driver confia apenas na porta de comunicação
   aberta pelo serviço (ACL restrita a SYSTEM). Mensagens têm tamanho fixo e
   versão. O driver nunca faz parsing de conteúdo de arquivo.
2. **Serviço ↔ worker.** O worker recebe um handle de arquivo somente
   leitura e devolve um veredito. Ele roda com token restrito, sem rede e
   sem escrita em disco. Se um arquivo explorar o parser (libclamav, PE), o
   dano fica no worker, que é descartado e reiniciado.
3. **Serviço ↔ UI/CLI.** Named pipe com ACL: leitura para usuários
   interativos, mudanças de política só para administradores.
4. **Internet.** Blocklists, assinaturas e regras são dados não
   confiáveis: baixados só por HTTPS, validados antes de substituir a versão
   em uso, com limite de tamanho, e nunca executados.

## Fluxo de decisão

```
evento (consulta DNS / abertura de arquivo)
   │
   ├─ allowlist (hash, caminho, publisher, domínio)  ── casou → PERMITIR
   │
   ├─ cache de vereditos (hash)                      ── casou → veredito em cache
   │
   ├─ motores (blocklist / ClamAV / YARA / PE / reputação)
   │
   └─ veredito: Clean | Suspicious | Malicious  → log estruturado + evento para a UI
```

A allowlist vem **antes** dos motores. Um falso positivo é tratado como bug crítico.

## Filtro DNS (Fase 1)

```
cliente ─UDP/TCP─► server.rs ─► resolver.rs
                                  │
                                  ├─ localhost / canário do Firefox → resposta local
                                  ├─ Policy::check(nome)
                                  │     allowlist (prioridade) → blocklists (ArcSwap<Snapshot>)
                                  │     bloqueado → 0.0.0.0/:: ou NXDOMAIN
                                  ├─ nome sem ponto → NXDOMAIN local
                                  ├─ Cache (chave: nome, tipo, classe, DO, CD)
                                  ├─ forward_zones → DNS comum (UDP, TCP se truncar)
                                  ├─ UpstreamPool → DoH (Quad9 → Cloudflare, backoff em falhas)
                                  └─ alvos de CNAME rechecados na política antes de responder
```

Módulos de `crates/dns/src`:

| Módulo | Responsabilidade |
|--------|------------------|
| `server.rs` | Laços UDP/TCP, limite de concorrência, framing TCP, timeout de ociosidade. |
| `resolver.rs` | Ordem de decisão, logs e eventos por consulta, estatísticas. |
| `blocklist/` | `Policy` (allowlist + snapshot), parsers (`hosts`, `domains`, `urls`) e atualizador. |
| `domain.rs` | Normalização e `DomainSet` (hash por sufixo, O(rótulos) por consulta). |
| `cache.rs` | Cache por TTL, negativas via SOA (RFC 2308), despejo por expiração. |
| `upstream.rs` | Cliente DoH (RFC 8484, POST, ID 0) e pool com fallback ordenado. |
| `http.rs` | Resolução de nomes para o próprio tráfego HTTP do Argus, direto pelo DoH. |
| `forward.rs` | Zonas locais encaminhadas a servidores DNS comuns. |
| `message.rs` | Construção de respostas, EDNS, truncamento UDP (limite de 1232 bytes). |
| `service.rs` | `DnsService`: montagem, bind, tarefas em segundo plano. API que o serviço da Fase 3 vai usar. |

### Por que não depende do DNS do sistema

O DNS do Windows vai apontar para o próprio Argus. Por isso:

- os clientes DoH conectam por IPs de **bootstrap** fixos na configuração, e
  qualquer outro nome é recusado (`NoResolve`);
- os downloads de blocklists resolvem nomes **direto nos upstreams DoH**
  (`PoolResolver`), sem passar pelo cache nem pelas blocklists;
- os hosts dos upstreams e das listas entram numa allowlist interna (nome
  exato), para que uma lista errada não impeça o Argus de se atualizar.

## Configuração

Um único arquivo TOML (`config/argus.example.toml`) com seções por
componente (`[log]`, `[dns]` e, nas próximas fases, `[scanner]`,
`[realtime]`, `[quarantine]`). Todos os campos têm padrão; campos
desconhecidos são erro, para pegar erros de digitação.

## Logs

`tracing` com saída no console (legível ou JSON) e arquivo JSON opcional com
rotação diária. Alvos estáveis permitem filtrar:

| Target | Conteúdo | Nível |
|--------|----------|-------|
| `argus_dns::blocked` | consulta bloqueada (`name`, `qtype`, `list`, `matched`, `client`) | WARN |
| `argus_dns::allowed` | bloqueio ignorado pela allowlist (`rule`, `overridden`) | INFO |
| `argus_dns::query` | demais consultas (`rcode`, `source`, `duration_us`) | DEBUG |
| `argus_dns::stats` | contadores a cada 5 min | INFO |

Além do log, `Resolver::subscribe()` entrega um `Event::DnsQuery` por consulta,
para o serviço repassar à UI.
