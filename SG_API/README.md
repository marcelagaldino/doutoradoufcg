# Instruções para execução do SG_API

O SG_API é executado em todas as VMs de gerenciamento.


## Pré-requisitos

Antes de executar a solução, garanta as seguintes versões:

- **Golang**: **1.18.1**
  - Verifique:
    ```bash
    go version
    ```
    Saída esperada (exemplo):
    ```
    go version go1.18.1 linux/amd64
    ```

- **etcd**: **3.3.25**
  - Verifique:
    ```bash
    etcd --version
    ```
    Saída esperada (exemplo):
    ```
    etcd Version: 3.3.25
    Git SHA: Not provided (use ./build instead of go build)
    Go Version: go1.18.1
    Go OS/Arch: linux/amd64
    ```

## Executar SG_API

Antes de iniciar a **SG_API**, é necessário popular o banco de dados do `etcd` com as informações das VMs com TPM.  

Cada entrada deve ter:
- **Chave**: ID da VM.  
- **Valor**: quantidade de VMgs ancoradas por ela, seguida pelo endereço IP e porta da VMg.

Exemplo de configuração:
```bash
etcdctl put metric-aa1f669b-545e-48ae-9c03-4a1d6c4f77f3 0,10.1.4.130:5051
```
Em seguida, é possível executar a SG_API:

```bash
go run main_mtls.go
```






