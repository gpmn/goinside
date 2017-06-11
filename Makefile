all:clean inside inject  dummy

clean:
	- rm -rf ${GOPATH}/bin/libgoinside.so bin/test bin/libgoinside.h bin/dummy bin/goinject

inside:
	cd goinside && go build -buildmode=c-shared -o ${GOPATH}/bin/libgoinside.so
	ls -l ${GOPATH}/bin/libgoinside.so

inject:
	cd goinject && go build -o ../bin/goinject && ls -l  ../bin/goinject

dummy:
	gcc test/dummy.c -o bin/dummy -ldl -O0
