INSTALL_DIR=modules
ifneq (${KERNELRELEASE},)
	obj-m := vmaas.o
endif

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
