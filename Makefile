obj-m += rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

cServer:
	gcc -g server.c -o uServer -lpthread

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
