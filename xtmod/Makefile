XTLIB_DIR := /lib/xtables
libxt_bigblocklist.so: libxt_bigblocklist.o 
	gcc -shared -fPIC -o $@ $^;
libxt_bigblocklist.o: libxt_bigblocklist.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;
lib_install: libxt_bigblocklist.so
	cp -f libxt_bigblocklist.so ${XTLIB_DIR}
	chown root:root ${XTLIB_DIR}/libxt_bigblocklist.so
	chmod 0644 ${XTLIB_DIR}/libxt_bigblocklist.so
libxt_bigblocklist6.so: libxt_bigblocklist6.o 
	gcc -shared -fPIC -o $@ $^;
libxt_bigblocklist6.o: libxt_bigblocklist6.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;
lib6_install: libxt_bigblocklist6.so
	cp -f libxt_bigblocklist6.so ${XTLIB_DIR}
	chown root:root ${XTLIB_DIR}/libxt_bigblocklist6.so
	chmod 0644 ${XTLIB_DIR}/libxt_bigblocklist6.so
install: lib_install lib6_install modules_install


MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
obj-m += xt_bigblocklist.o
obj-m += xt_bigblocklist6.o
all: libxt_bigblocklist.so libxt_bigblocklist6.so
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install: 
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;


