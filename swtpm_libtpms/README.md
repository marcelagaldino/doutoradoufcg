#Instruções para instalação do SWTPM e libtpms

.

## Pré-requisitos

Antes de prosseguir, instale as dependências necessárias executando:

```bash
sudo apt-get update -y
sudo apt-get install -y automake expect gnutls-bin libgnutls28-dev git gawk m4 socat fuse libfuse-dev tpm-tools libgmp-dev libtool libglib2.0-dev libnspr4-dev libnss3-dev libssl-dev libtasn1-dev
sudo apt-get clean
sudo apt install -y autoconf findutils gnutls-dev net-tools python3-twisted sed socat softhsm2 libseccomp-dev
```
## Instalação

Após instalar as dependências, execute o script abaixo (presente neste diretório) para instalar o SWTPM e o libtpms:

```bash
./install.sh
```
