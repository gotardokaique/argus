# Argus

Antivírus open source para Windows, construído em camadas: filtro DNS,
scanner sob demanda, monitoramento em tempo real e um driver minifilter que
bloqueia a execução de arquivos maliciosos antes de eles rodarem.

O Argus é uma **camada adicional** ao Microsoft Defender, não um substituto.
Projeto pessoal, licenciado sob a **GPLv2** (exigência da libclamav).

## Objetivos

- **Proteção em tempo real**: um driver de kernel intercepta a abertura e a
  execução de arquivos e pergunta ao serviço se pode prosseguir.
- **Scanner sob demanda**: arquivo, pasta ou disco inteiro (ClamAV, YARA-X,
  análise de PE, reputação por hash).
- **Filtro DNS local**: bloqueia domínios de malware e phishing, de forma que
  outros apps não consigam contorná-lo.
- **Quarentena**: move e cifra o arquivo, com opção de restaurar.
- **Atualização automática** de assinaturas, regras YARA e blocklists.
- **UI desktop**: status, scans, quarentena, logs, domínios bloqueados e allowlist.
- **Logs estruturados** de todos os vereditos.

## Princípios

- Rust em todo o user-mode. C só no driver. Nenhum parsing de arquivo não
  confiável em C, exceto dentro da libclamav.
- O driver é mínimo: intercepta e pergunta. Toda decisão fica no serviço.
  Timeout configurável, com fail-open por padrão, para nunca travar o sistema.
- O scan roda em um processo worker separado e de baixo privilégio.
- Falso positivo é bug crítico: allowlist por hash, caminho e publisher.
- O driver é desenvolvido e testado só em VM Hyper-V (test signing + WinDbg).
- Configuração em TOML. UI com componentes e padrões do shadcn/ui.

Detalhes em [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/ROADMAP.md](docs/ROADMAP.md) e [docs/DECISIONS.md](docs/DECISIONS.md).

## Estado atual

| Fase | Componente | Estado |
|------|------------|--------|
| 1 | Filtro DNS local (`argus-dns`) | **pronto (console)** |
| 2 | Scanner sob demanda via CLI | planejado |
| 3 | Windows Service, monitoramento user-mode, quarentena | planejado |
| 4 | Driver minifilter | planejado |
| 5 | UI em Tauri | planejado |
| 6 | Provider AMSI e enforcement de DNS via WFP | planejado |

## Estrutura

```
driver/          minifilter em C + WDK (Fase 4)
crates/core      tipos compartilhados: config, veredito, eventos, logging
crates/scanner   ClamAV (FFI), YARA-X, goblin, hashes (Fase 2)
crates/dns       filtro DNS local (Fase 1)
crates/service   Windows Service (Fase 3)
crates/cli       linha de comando (Fase 2)
ui/              Tauri + React/TypeScript + shadcn/ui (Fase 5)
rules/           regras YARA
config/          configuração de exemplo
docs/            arquitetura, roadmap, decisões
```

## Compilar

Requisitos: Windows 10/11 x64, Rust estável (1.88+) com toolchain MSVC.

```powershell
cargo build --release -p argus-dns
cargo test --workspace
```

O binário fica em `target\release\argus-dns.exe`.

## Filtro DNS (Fase 1)

### O que ele faz

- Escuta em `127.0.0.1:53` e `[::1]:53`, UDP e TCP.
- Encaminha as consultas por **DNS-over-HTTPS** para Quad9 e Cloudflare
  (variante *security*, que também bloqueia malware), com fallback automático.
- Baixa e atualiza blocklists públicas (URLhaus, phishing-filter e Phishing
  Army por padrão) e bloqueia o domínio listado **e seus subdomínios**.
- Também bloqueia respostas cujo CNAME aponta para um domínio bloqueado.
- A allowlist tem prioridade sobre todas as listas.
- Resposta para domínio bloqueado: `0.0.0.0`/`::` (padrão) ou NXDOMAIN.
- Faz cache das respostas respeitando o TTL (inclusive o das respostas negativas).
- Registra cada consulta bloqueada em log estruturado (console e, se quiser, arquivo JSON).

### Rodar

```powershell
# Opcional: copie e ajuste a configuração
copy config\argus.example.toml argus.toml

.\target\release\argus-dns.exe                       # usa .\argus.toml se existir
.\target\release\argus-dns.exe --config C:\caminho\argus.toml
.\target\release\argus-dns.exe --check               # só valida a configuração
```

Não é preciso ser administrador para abrir a porta 53 no Windows. Na primeira
execução as listas são baixadas em segundo plano (alguns segundos). Depois
elas ficam em cache em `%ProgramData%\Argus\blocklists` e são carregadas na
hora, mesmo sem rede.

Para ver todas as consultas, não só as bloqueadas:

```powershell
$env:RUST_LOG = "info,argus_dns=debug"; .\target\release\argus-dns.exe
```

### Testar antes de mudar o DNS do sistema

Com o `argus-dns` rodando:

```powershell
Resolve-DnsName example.com     -Server 127.0.0.1 -DnsOnly   # IP real
Resolve-DnsName amiprotected.it -Server 127.0.0.1 -DnsOnly   # 0.0.0.0 (domínio de teste do Phishing Army)
```

### Apontar o DNS do Windows para o Argus

> **Importante:** enquanto o DNS do sistema apontar para `127.0.0.1`, o
> `argus-dns` precisa estar rodando. Se ele parar, nenhum nome resolve. Guarde
> o comando de reversão abaixo.

Pelo PowerShell **como Administrador**:

```powershell
# 1. Descubra o nome da interface em uso (ex.: "Wi-Fi" ou "Ethernet")
Get-NetAdapter | Where-Object Status -eq 'Up' | Format-Table Name, InterfaceDescription

# 2. Anote a configuração atual (útil se você usava DNS fixo)
Get-DnsClientServerAddress -InterfaceAlias "Wi-Fi"

# 3. Aponte IPv4 e IPv6 para o Argus e limpe o cache do Windows
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses ("127.0.0.1", "::1")
Clear-DnsClientCache

# 4. Confira
Resolve-DnsName amiprotected.it   # deve responder 0.0.0.0
```

Pela interface gráfica: **Configurações → Rede e Internet → Wi-Fi (ou
Ethernet) → Propriedades de hardware → Atribuição de servidor DNS → Editar →
Manual**. Ative IPv4 com `127.0.0.1` e IPv6 com `::1`, e deixe a criptografia
de DNS como **Não criptografado**: a criptografia (DoH) acontece entre o
Argus e o upstream.

Repita para cada interface que você usa (Wi-Fi e cabo, por exemplo).

### Reverter

```powershell
# Como Administrador: volta ao DNS recebido por DHCP
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
Clear-DnsClientCache
```

Se você usava servidores fixos, use de novo os que anotou no passo 2. Pela
interface gráfica, volte "Atribuição de servidor DNS" para **Automático (DHCP)**.

### Limitações conhecidas (Fase 1)

- **DNS próprio dos navegadores**: Chrome/Edge com "Usar DNS seguro" e um
  provedor *personalizado*, ou Firefox com DoH no modo "proteção máxima",
  contornam o filtro. O Argus responde NXDOMAIN para
  `use-application-dns.net`, o que desliga o DoH automático do Firefox, mas
  não as configurações manuais. O bloqueio forçado via WFP chega na Fase 6.
- **VPNs** costumam impor o próprio DNS enquanto conectadas.
- **Nomes da rede local** (`roteador.lan`, `nas.home.arpa`) deixam de resolver
  pelo upstream. Configure `[[dns.forward_zones]]` apontando para o roteador
  (veja `config/argus.example.toml`).
- Proxy HTTP do sistema não é usado nos downloads das listas nem no DoH.

### Problemas comuns

- **"nenhum endereço de escuta disponível"**: outro programa usa a porta 53.
  Descubra qual com
  `Get-NetUDPEndpoint -LocalPort 53 | Select LocalAddress, OwningProcess` e
  `Get-Process -Id <pid>`. O Compartilhamento de Conexão (ICS) e alguns
  emuladores/VMs abrem um DNS próprio.
- **IPv6 desabilitado**: o bind em `[::1]:53` falha com um aviso e o Argus
  segue só com IPv4.
- **Site legítimo bloqueado**: o log mostra a lista e a entrada responsáveis
  (`list=... matched=...`). Adicione o domínio em `dns.allowlist` e reinicie.

## Licença

GPL versão 2 ([LICENSE](LICENSE)). As blocklists têm termos próprios; veja os
comentários em `config/argus.example.toml`.
