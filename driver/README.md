# driver — minifilter (Fase 4)

Minifilter em C + WDK. Responsabilidade única: interceptar a criação/execução
de arquivos, perguntar ao `argus-service` via `FilterConnectCommunicationPort`
e aplicar a resposta. Nenhuma decisão é tomada aqui. Timeout configurável,
com fail-open por padrão.

**Regra:** desenvolvido e testado somente em VM Hyper-V com test signing,
Driver Verifier e WinDbg. Nunca carregar na máquina host.
