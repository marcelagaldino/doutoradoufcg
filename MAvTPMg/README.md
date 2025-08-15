# Instruções para o carregamento do módulo de kernel **MAvTPMg**

Nos Hosts que compõem o sistema executar:

```bash
sudo apt-get install build-essential linux-headers-$(uname -r)
sudo make
sudo insmod vmaas.ko


