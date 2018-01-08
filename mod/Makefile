obj-m += dkm.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	find . ! -regex ".*\.\(c\|h\|txt\|tar\|ko\)" -a ! -name "Makefile" -delete
	find . -name '*.mod.*' -delete
clean:
	#find . ! -regex ".*\.\(c\|h\|txt\|tar\)" -a ! -name "Makefile" -delete
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	

