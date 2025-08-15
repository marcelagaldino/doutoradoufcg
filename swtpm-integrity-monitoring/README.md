# Instruções para execução do Agent-Host



## Pré-requisitos

Antes de executar a solução, garanta a seguinte versão:

- **Golang**: **1.18.1**

  Verifique:
    ```bash
    go version
    ```
    Saída esperada (exemplo):
    ```
    go version go1.18.1 linux/amd64
    ```

## Executar Agent-Host

- Edite o arquivo de configuração agent-host/conf.yaml, informando o UUID da VM de gerenciamento, bem como seu endereço IP e a porta utilizada para comunicação com a SG_API.

- O Agent-Host deve ser executado em cada máquina hospedeira que compõe o sistema.

- Se o Host dispor de chip TPM execute:

 ```bash
    go run agent-host-ancoragem-local-experimento.go
 ```

- Se o Host não dispor de chip TPM execute:

 ```bash
    go run agent-host-ancoragem-remota-experimento.go
   ```
