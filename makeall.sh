#!/bin/bash

rm -rf test/libgoinside.so test/test
go build -buildmode=c-shared -o test/libgoinside.so 
#g++ Test/test.cpp -o Test/test -lgoinside -L./Test -I./Test
gcc test/dummy.c -o test/dummy -ldl -O0
