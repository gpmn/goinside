package main

import (
	"C"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/rpc"
)

const minRPCPort = 10000
const maxRPCPort = 11000

// GoinRPC :
type GoinRPC struct {
}

// EnumSymbols : 	name 	- symbol's name
//					maxCnt	- maxCnt to return
func (r *GoinRPC) EnumSymbols(totalCntPtr *int /*outparam*/, rss []RemoteSymbol /*outparam*/, name string, maxCnt int) error {
	fmt.Printf("EnumSymbols(%s,%d) is called\n", name, maxCnt)
	return nil
}

// GetSymbol : 		name 	- symbol's name
//					idx		- -1, first of the symbols; else the index of the wanted symbols
func (r *GoinRPC) GetSymbol(sym *RemoteSymbol /*outparam*/, name string, idx int) error {
	fmt.Printf("GetSymbol(%s,%d) is called\n", name, idx)
	return nil
}

// GetBuffer :		addr	- address to dump
//					cnt		- count of bytes to Get
func (r *GoinRPC) GetBuffer(content []byte /*out param*/, addr uintptr, cnt int) (err error) {
	fmt.Printf("GetBuffer(0x%x,%d) is called\n", addr, cnt)
	return nil
}

// SetBuffer : 		addr	- address to set
//					cnt		- count of bytes to copy
//					content	- content to set
func (r *GoinRPC) SetBuffer(addr uintptr, cnt int, content []byte) (err error) {
	fmt.Printf("SetBuffer(0x%x,%d,%v) is called\n", addr, cnt, content)
	return nil
}

// Call :          funcName	- callee function's name
//					   args	- args of funcName
func (r *GoinRPC) Call(res uint64 /*out param*/, funcName string, args ...interface{}) (err error) {
	fmt.Printf("Call -- %s %v\n", funcName, args)
	return nil
}

//export goinRPCInit
func goinRPCInit() {
	rpc.Register(new(GoinRPC))
	rpc.HandleHTTP()
	l, e := net.Listen("tcp", ":0")
	if e != nil {
		log.Fatal("listen error:", e)
	}
	go http.Serve(l, nil)
	fmt.Printf("GoinRPC serve @ %s\n", l.Addr().String())
}
