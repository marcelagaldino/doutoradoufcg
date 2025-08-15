# Instruções para o carregamento do módulo de kernel **MAvTPMg**

Em todos os Hosts com TPM, executar:

```bash
sudo apt-get install build-essential linux-headers-$(uname -r)
sudo make
sudo insmod vmaas.ko


