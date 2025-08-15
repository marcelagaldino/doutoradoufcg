# Instruções para o carregamento do módulo de kernel **MAvTPMu**

Em todas as VMs de gerenciamento, executar:

```bash
sudo apt-get install build-essential linux-headers-$(uname -r)
sudo make
sudo insmod vmaas.ko
