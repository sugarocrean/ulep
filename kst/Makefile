BASEDIR := /lib/modules/$(shell uname -r)
KERNEL_SRC_TREE ?= $(BASEDIR)/build
PWD :=$(shell pwd)

param-objs := kst.o
obj-m := param.o

ifneq ($(KERNELRELEASE),)
else

all:
	make -C $(KERNEL_SRC_TREE) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order
endif
