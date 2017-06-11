BINDIR:=${GOPATH}/bin
all:clean dummy
	go build -buildmode=c-shared -o ${BINDIR}/libgoinside.so
	go build -o ${BINDIR}/goinject
	file ${BINDIR}/libgoinside.so
	file ${BINDIR}/goinject

clean:
	- rm -rf ${BINDIR}/libgoinside.so ${BINDIR}/test ${BINDIR}/libgoinside.h ${BINDIR}/dummy ${BINDIR}/goinject

dummy:
	gcc test/dummy.c -o ${BINDIR}/dummy -ldl -O0
