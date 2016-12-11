KDIR := /lib/modules/$(shell uname -r)/build
obj-m += rfc.o
obj-m += list_vectors.o
obj-m += setvector.o
obj-m += mkdir-test.o
obj-m += list_pid_sv.o
obj-m += clone-test.o
obj-m += clone2-test.o

all: rfc list_vectors setvector mkdir-test list_pid_sv clone-test clone2-test

rfc: rfc.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi rfc.c -I$(KDIR)/include -o rfc
list_vectors: list_vectors.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi list_vectors.c -I$(KDIR)/include -o list_vectors
setvector: setvector.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi setvector.c -I$(KDIR)/include -o setvector
mkdir-test: mkdir-test.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi mkdir-test.c -I$(KDIR)/include -o mkdir-test
list_pid_sv: list_pid_sv.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi list_pid_sv.c -I$(KDIR)/include -o list_pid_sv
clone-test: clone-test.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi clone-test.c -I$(KDIR)/include -o clone-test
clone2-test: clone2-test.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi clone2-test.c -I$(KDIR)/include -o clone2-test
clean:
	rm -f rfc list_vectors setvector mkdir-test list_pid_sv clone-test clone2-test
