KDIR=/lib/modules/$(shell uname -r)/build
  
CFLAGS_user = -std=gnu11 -Wall -Wextra -Werror
LDFLAGS_user = -lpthread

obj-m += simple.o
simple-objs := \
        main.o

all: 
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
