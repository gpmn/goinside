package main // stand on goinside or goinject

import (
	"debug/elf"
	"fmt"
)

// RemoteSymbol :
type RemoteSymbol struct {
	elf.Symbol
	libPath string
}

// GoInExports :
var GoInExports = map[string]interface{}{
	"Stub":   Stub,
	"Lookup": Lookup,
	"Exec":   Exec,
	"D":      D,
	"M":      M,
}

// Stub :
func Stub() {
	fmt.Printf("Stub is called\n")
}

// Lookup :
func Lookup(sym string, idx int) ([]RemoteSymbol, error) {
	fmt.Printf("Lookup is called\n")
	return nil, nil
}

// Exec :
func Exec(sym string, args []interface{}) (res uint64, err error) {
	fmt.Printf("Exec is called\n")
	return 0, nil
}

// D :
func D(addr uintptr) (cont []byte, err error) {
	fmt.Printf("D is called\n")
	return nil, err
}

// M :
func M(addr uintptr) (cont []byte, err error) {
	fmt.Printf("M is called\n")
	return nil, err
}
