all:clean dummy goinside

clean:
	- rm -rf bin/libgoinside.so bin/test bin/libgoinside.h 

goinside:
	cd goinside && go build -buildmode=c-shared -o ../bin/libgoinside.so

dummy:
	gcc test/dummy.c -o bin/dummy -ldl -O0


