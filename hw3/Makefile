obj-m := fsl_os_svector.o
obj-m += fsl_os_svector1.o
obj-m += fsl_os_svector2.o
obj-m += fsl_os_sci.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: fsl_os_svector fsl_os_svector1 fsl_os_svector2 fsl_os_sci

fsl_os_svector:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
fsl_os_svector1:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
fsl_os_svector2:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
fsl_os_sci:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
