package main

import (
	"C"
	"flag"
	"fmt"
	"os"

	"github.com/gpmn/goinside/goinside"
)

func main() {
	pidptr := flag.Int("pid", 0, "target process's pid")
	flag.Parse()
	if *pidptr < 0 {
		fmt.Printf("-pid param invalid ,please supply target pid!(0 means self)")
		os.Exit(-1)
	}
	err := goinside.Inject(*pidptr, "/home/golang/gopath/bin/libgoinside.so")
	if nil == err {
		fmt.Printf("Inject success!")
	} else {
		fmt.Printf("Inject failed, error %s\n", err)
	}
}
