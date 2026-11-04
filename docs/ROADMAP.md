# Roadmap

## Fase 1 — Filtro DNS local ✅

- [x] Resolver em `127.0.0.1:53` e `[::1]:53`, UDP e TCP
- [x] Upstream DoH configurável (Quad9 e Cloudflare *security*) com fallback e backoff
- [x] Blocklists públicas: urlhaus-filter, phishing-filter, Phishing Army (OpenPhish opcional)
- [x] Formatos `hosts`, `domains` e `urls`; deduplicação; match de subdomínio
- [x] Download periódico com ETag, espelhos, validação e cache em disco
- [x] Allowlist com prioridade
- [x] Resposta configurável: `0.0.0.0`/`::` ou NXDOMAIN
- [x] Cache respeitando TTL (positivo e negativo)
- [x] Bloqueio por alvo de CNAME
- [x] Logs estruturados (`tracing`, console e JSON)
- [x] Binário de console `argus-dns`

Pendências conhecidas:

- [ ] Substituir `reqwest` por `hyper-util` + `hyper-tls` (o `sync_wrapper`,
      dependência do reqwest, é Apache-2.0, incompatível com a GPLv2). Ver D-007.
- [ ] Recarregar a allowlist sem reiniciar (virá pelo named pipe na Fase 3)
- [ ] `SO_EXCLUSIVEADDRUSE` na porta 53 contra sequestro da porta (Fase 3, junto do serviço)

## Fase 2 — Scanner sob demanda (CLI)

- [ ] `crates/scanner`: bindings da libclamav (FFI, `bindgen` + build da ClamAV)
- [ ] YARA-X com regras de `rules/` compiladas na carga
- [ ] Análise de PE com goblin (entropia por seção, imports suspeitos, assinatura Authenticode)
- [ ] Hash SHA-256 + cache de vereditos por hash
- [ ] Consulta opcional ao MalwareBazaar (hash, nunca o arquivo)
- [ ] Allowlist por hash, caminho e publisher
- [ ] `argus scan <arquivo|pasta|disco>` com saída humana e JSON
- [ ] Worker isolado de baixo privilégio já nesta fase (protocolo serviço ↔ worker)

## Fase 3 — Windows Service, monitoramento user-mode e quarentena

- [ ] `argus-service` (instalação, recuperação automática, logs no Event Log)
- [ ] Hospedar o `DnsService`; ACLs no `%ProgramData%\Argus`
- [ ] Monitoramento de Downloads e Temp (`ReadDirectoryChangesW`)
- [ ] Quarentena: mover + cifrar (AES-GCM, chave protegida por DPAPI de máquina), restaurar
- [ ] Named pipe com ACL para UI/CLI
- [ ] Atualização automática de assinaturas ClamAV e regras YARA

## Fase 4 — Driver minifilter

- [ ] Projeto WDK em `driver/`, test signing, VM Hyper-V dedicada + WinDbg
- [ ] Interceptar `IRP_MJ_CREATE` (execução) e mapeamento de seção de imagem
- [ ] `FilterConnectCommunicationPort` com mensagens de tamanho fixo
- [ ] Timeout configurável e fail-open por padrão; exclusão do próprio processo do serviço
- [ ] Testes de estresse (Driver Verifier) antes de qualquer uso fora da VM

## Fase 5 — UI em Tauri

- [ ] Tauri + React/TypeScript + shadcn/ui
- [ ] Telas: status geral, scans, quarentena, logs, domínios bloqueados, allowlist
- [ ] Comunicação exclusivamente pelo named pipe do serviço

## Fase 6 — AMSI e enforcement de DNS

- [ ] Provider AMSI (scripts PowerShell, VBScript, macros)
- [ ] WFP: bloquear DNS (53/853) e endpoints DoH conhecidos que não sejam o Argus
