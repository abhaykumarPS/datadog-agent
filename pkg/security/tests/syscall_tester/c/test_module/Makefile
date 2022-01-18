obj-m += test_module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	cp ./test_module.ko /tmp/test_module.ko

clean:
	- rm /tmp/test_module.ko
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
