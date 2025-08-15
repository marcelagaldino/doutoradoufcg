INSTALL_DIR=modules
ifneq (${KERNELRELEASE},)
    obj-m := VMAAS_VMG.o
endif

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
