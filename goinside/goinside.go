package main

import (
	"C"
	"bufio"
	"debug/elf"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	_ "github.com/go-errors/errors"
)

//LibraryInfoItem :
type LibraryInfoItem struct {
	Begin   uint64
	End     uint64
	LibPath string
}

//SymbolInfoEx :
type SymbolInfoEx struct {
	elf.Symbol
	libraryIdx int
}

//GetLibrary :
func (s *SymbolInfoEx) GetLibrary(procLibInfos []LibraryInfoItem) string {
	return procLibInfos[s.libraryIdx].LibPath
}

//export ParseEmbedded

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func collectLibInfos(pid int, procLibInfos *[]LibraryInfoItem) (res bool) {
	var err error
	// defer func() {
	//     if e := recover(); nil != e {
	//         fmt.Printf("collectLibInfos failed with error : %s\n", e)
	//      fmt.Println(e.(*errors.Error).ErrorStack())
	//         res = false
	//     }
	// }()

	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	check(err)
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var item LibraryInfoItem
		line := scanner.Text()
		strlst := strings.Fields(line)
		//fmt.Printf("%s\n", line)

		if strlst[1] != "r-xp" {
			continue
		}

		if len(strlst) < 6 ||
			strlst[5] == "" ||
			strings.HasPrefix(strlst[5], "[") ||
			strings.HasSuffix(strlst[5], "]") ||
			strings.HasSuffix(strlst[5], "libgoinside.so") {
			continue
		}

		item.LibPath = strlst[5]

		bestrs := strings.Split(strlst[0], "-")

		item.Begin, err = strconv.ParseUint(bestrs[0], 16, 64)
		check(err)

		item.End, err = strconv.ParseUint(bestrs[1], 16, 64)
		check(err)

		//fmt.Printf("0x%-16x   0x%-16x %s\n", item.Begin, item.End, item.LibPath)
		*procLibInfos = append(*procLibInfos, item)
	}

	return true
}

func parseSymbols(libPath string, libIdx int, mapSymbol map[string][]SymbolInfoEx) (res []SymbolInfoEx) {
	// defer func() {
	//     if e := recover(); nil != e {
	//         fmt.Printf("parseSymbols(%s) failed with error : %s\n", libPath, e)
	//      fmt.Println(e.(*errors.Error).ErrorStack())
	//         res = nil
	//     }
	// }()dlopenShellCode

	f, err := os.Open(libPath)
	check(err)
	defer f.Close()

	var ident [16]uint8
	f.ReadAt(ident[0:], 0)
	if ident[0] != '\x7f' || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
		fmt.Printf("Bad magic number at %d\n", ident[0:4])
		return nil
	}

	en, err := elf.NewFile(f)
	check(err)

	// for ii, ss := range(en.Sections){
	//  fmt.Printf("%02d - %s\n", ii, ss.Name);
	// }

	// fmt.Printf("\n\nLibaray     : %s\n", libPath)
	// fmt.Printf("ELF Type    : %s\n", en.Type)
	// fmt.Printf("ELF Data    : %s\n", en.Data)
	// fmt.Printf("Entry Point : 0x%x\n", en.Entry)
	// fmt.Printf("Class       : %s\n", en.Class.String())
	// fmt.Printf("Arch        : %s\n", en.Machine.String())

	//fmt.Printf("Symbols     :\n")
	symbols, err := en.Symbols()
	//var secDesc string

	if nil != err {
		fmt.Printf("    warning: %s's en.Symbols() got error : %s\n", libPath, err)
	} else {
		for _, s := range symbols {
			if s.Section == elf.SHN_UNDEF || s.Section >= elf.SHN_LORESERVE {
				//secDesc = elf.SectionIndex(s.Section).String()
				continue
			}
			//secDesc = en.Sections[s.Section].Name

			// fmt.Printf("%-5d I:%-12s O:%-12s Sec:%-12s Val:0x%-10x Size:0x%-6x name:%s\n",
			//  idx, elf.ST_BIND(s.Info), elf.ST_VISIBILITY(s.Other), secDesc, s.Value, s.Size, s.Name)
			syex := SymbolInfoEx{s, libIdx}
			if _, ok := mapSymbol[s.Name]; !ok {
				mapSymbol[s.Name] = make([]SymbolInfoEx, 0)
			}
			mapSymbol[s.Name] = append(mapSymbol[s.Name], syex)
		}
	}
	//fmt.Printf("DynamicSymbols     :\n")
	symbols, err = en.DynamicSymbols()
	if nil != err {
		fmt.Printf("%s's en.DynamicSymbols() got error : %s\n", libPath, err)
	} else {
		for _, s := range symbols {
			if s.Section == elf.SHN_UNDEF || s.Section >= elf.SHN_LORESERVE {
				//secDesc = elf.SectionIndex(s.Section).String()
				continue
			}
			//secDesc = en.Sections[s.Section].Name

			// fmt.Printf("%-5d I:%-12s O:%-12s Sec:%-12s Val:0x%-10x Size:0x%-6x name:%s\n",
			//  idx, elf.ST_BIND(s.Info), elf.ST_VISIBILITY(s.Other), secDesc, s.Value, s.Size, s.Name)
			syex := SymbolInfoEx{s, libIdx}
			if _, ok := mapSymbol[s.Name]; !ok {
				mapSymbol[s.Name] = make([]SymbolInfoEx, 0)
			}
			mapSymbol[s.Name] = append(mapSymbol[s.Name], syex)

		}
	}

	return nil
}

func parseProc(pid int) ([]LibraryInfoItem, map[string][]SymbolInfoEx) {
	var procLibInfos []LibraryInfoItem
	collectLibInfos(pid, &procLibInfos)

	mapSymbol := make(map[string][]SymbolInfoEx)
	for idx, item := range procLibInfos {
		parseSymbols(item.LibPath, idx, mapSymbol)
	}
	return procLibInfos, mapSymbol
}

var libraryArray []LibraryInfoItem
var symbolMap map[string][]SymbolInfoEx

//ParseEmbedded :
//export ParseEmbedded
func ParseEmbedded() {
	libraryArray, symbolMap = parseProc(os.Getpid())
}

// if name not found
//      return (sym, 0)
// if idx < 0
//      if there's only one item has the required name, then return the sole one's (sym, addr)
//      if there're several items share the same name, then return (sym, 1)
// if idx >= 0
//      return the one asked for if valid (sym,addr)
//      return (sym, 2) if out range
func getSymbolByName(symName string, idx int, libArr []LibraryInfoItem, symMap map[string][]SymbolInfoEx) (sym SymbolInfoEx, addr uintptr) {
	if _, ok := symMap[symName]; !ok {
		return sym, 0
	}
	//check idx to see if caller know there're may item has the same name
	if idx < 0 && len(symMap[symName]) > 1 {
		return sym, 1
	}
	if idx > len(symMap[symName]) {
		return sym, 2
	}
	sym = symMap[symName][idx] //TODO:: many itemes have the same name ???
	fmt.Printf("got sym %v\n", sym)
	lib := libArr[sym.libraryIdx]
	addr = uintptr(lib.Begin + sym.Value)
	return sym, addr
}

func getBytesFromUint64(val uint64) [8]byte {
	return [8]byte{
		byte((val >> 56) & 0xff),
		byte((val >> 48) & 0xff),
		byte((val >> 40) & 0xff),
		byte((val >> 32) & 0xff),
		byte((val >> 24) & 0xff),
		byte((val >> 16) & 0xff),
		byte((val >> 8) & 0xff),
		byte((val >> 0) & 0xff),
	}
}

func showWaitStatus(desc string, ws syscall.WaitStatus) {
	var res string
	if ws.Continued() {
		res += "Continued "
	}

	if ws.CoreDump() {
		res += "CoreDump "
	}

	res += fmt.Sprintf("ExitStatus%d ", ws.ExitStatus())

	if ws.Exited() {
		res += "Exited "
	}

	res += fmt.Sprintf("Signal%d ", ws.Signal())

	if ws.Signaled() {
		res += "Signaled "
	}
	res += fmt.Sprintf("StopSignal%d ", ws.StopSignal())
	if ws.Stopped() {
		res += "Stopped "
	}
	res += fmt.Sprintf("TrapCause%d", ws.TrapCause())
	fmt.Printf("%s - ws 0x%x %s\n", desc, ws, res)
}

func inject(pid int, injectLibPath string, libArr []LibraryInfoItem, symMap map[string][]SymbolInfoEx, overlapFunc string) error {
	// void* dlopen_wrapper(void*(*dlopen_ptr)(const char* , int ), const char* path, int flag){
	//       return dlopen_ptr(path, flag);
	// }

	// 00000000000008f0 <dlopen_wrapper>:
	// 8f0:	55                   	push   %rbp
	// 8f1:	48 89 e5             	mov    %rsp,%rbp
	// 8f4:	48 83 ec 20          	sub    $0x20,%rsp
	// 913:	ff d0                	callq  *%rax
	//		add int 3 [0xcc] here
	// 915:	c9                   	leaveq ---- change to int3 [0xcc] at here
	// 916:	c3                   	retq

	var ws syscall.WaitStatus
	var backupCode [128]byte
	var backupStack [1024]byte
	var backupRegs syscall.PtraceRegs
	dlopenShellCode := []byte{
		0x55,
		0x48, 0x89, 0xe5,
		0x48, 0x83, 0xec, 0x20,
		0xff, 0xd0,
		0xcc, // int 3
		0xc9,
		0xc3,
		0x90, // nop
		0x90, // nop
	}

	_, err := os.Stat(injectLibPath)
	if nil != err {
		fmt.Printf("lib %s can not be stat, error : %s\n", injectLibPath, err)
	}

	_, addrDlopen := getSymbolByName("dlopen", 0, libArr, symMap)
	if addrDlopen < 4 {
		fmt.Printf("getSymbolByName(dlopen) failed, dlopen not found!\n")
		return fmt.Errorf("dlopen not found")
	}

	if overlapFunc == "" {
		overlapFunc = "main"
	}

	_, addrOverlap := getSymbolByName(overlapFunc, 0, libArr, symMap)
	if addrOverlap < 4 {
		fmt.Printf("getSymbolByName(%s) failed, dlopen not found!\n", overlapFunc)
		return fmt.Errorf("overlapFunc %s not found", overlapFunc)
	}

	fmt.Printf("addrDlopen - 0x%x, overlap %s - 0x%x\n", addrDlopen, overlapFunc, addrOverlap)

	err = syscall.PtraceAttach(pid)
	if nil != err {
		fmt.Printf("PtraceAttach(%s) failed, error %s!\n", os.Args[1], err)
		return err
	}
	defer syscall.PtraceDetach(pid)

	if _, err = syscall.Wait4(pid, &ws, syscall.WUNTRACED, nil); nil != err {
		fmt.Printf("Wait4(%d) failed, error %s!\n", pid, err)
		return err
	}
	showWaitStatus("expecting a stop signal", ws)

	// 1.peek and backup stack/code/regs
	if err = syscall.PtraceGetRegs(pid, &backupRegs); nil != err {
		fmt.Printf("PtraceGetReg pid%d failed, error %s!\n", pid, err)
		return err
	}
	// backup regs for later use
	regs := backupRegs
	// TODO:: check PC, should not within libdl.so.

	if _, err = syscall.PtracePeekData(pid, uintptr(regs.Rsp-uint64(len(backupStack))), backupStack[0:]); nil != err {
		fmt.Printf("PtracePeekData of stack @ (0x%x - 0x%x) failed, error %s!\n", regs.Rsp, len(backupStack), err)
		return err
	}

	if _, err = syscall.PtracePeekText(pid, addrOverlap, backupCode[0:]); nil != err {
		fmt.Printf("PtracePeekText of code @ 0x%x failed, error %s!\n", addrOverlap, err)
		return err
	}

	// prepare inject code
	injectCode := append(dlopenShellCode, []byte(injectLibPath)...)
	injectCode = append(injectCode, []byte{0x00, 0x00}...)
	// 3.change code @ addrOverlap
	if _, err = syscall.PtracePokeData(pid, addrOverlap, injectCode); nil != err {
		fmt.Printf("PtracePokeData of injectCode @ codeseg:0x%x failed, error %s!\n", addrOverlap, err)
		return err
	}

	regs.Rax = uint64(addrDlopen)                                 // inner func ptr
	regs.Rdi = uint64(addrOverlap) + uint64(len(dlopenShellCode)) // entry of shell code
	regs.Rsi = 0x101                                              // RTLD_LAZY | RTLD_GLOBAL
	regs.SetPC(uint64(addrOverlap))

	// 4. setup regs,
	if err = syscall.PtraceSetRegs(pid, &regs); nil != err {
		fmt.Printf("PtraceSetRegs failed, error %s!\n", err)
		return err
	}

	// 5. restart tracee
	if err = syscall.PtraceCont(pid, 0); nil != err {
		fmt.Printf("PtraceCont failed, error %s!\n", err)
		return err
	}

	if _, err = syscall.Wait4(pid, &ws, syscall.WUNTRACED, nil); nil != err { // wait for trap
		fmt.Printf("Wait4 tracee's trap signal failed, error : %s!\n", err)
		return err
	}

	showWaitStatus("expecting a trap signal", ws)

	// get regs to see if dlopen success
	if err = syscall.PtraceGetRegs(pid, &regs); nil != err {
		fmt.Printf("PtraceGetReg pid%d failed, error %s!\n", pid, err)
		return err
	}

	if regs.Rax == 0 {
		fmt.Printf("dlopen's failed -- regs.Rax : 0x%x\n", regs.Rax)
	} else {
		fmt.Printf("dlopen's OK, handle : 0x%x\n", regs.Rax)
	}

	// 6. restore code
	if _, err = syscall.PtracePokeText(pid, addrOverlap, backupCode[0:]); nil != err {
		fmt.Printf("PtracePokeText restore code @ 0x%x failed, error : %s!\n", addrOverlap, err)
		return err
	}

	// 7. restore stack
	if _, err = syscall.PtracePokeData(pid, uintptr(backupRegs.Rsp-uint64(len(backupStack))), backupStack[0:]); nil != err {
		fmt.Printf("PtracePokeData restore stack @ (0x%x - 0x%x) failed, error : %s!\n", backupRegs.Rsp, len(backupStack), err)
		return err
	}

	// 8. restore regs
	if err = syscall.PtraceSetRegs(pid, &backupRegs); nil != err {
		fmt.Printf("PtraceSetregs restore failed, error : %s!\n", err)
		return err
	}

	// 9. restart tracee
	if err = syscall.PtraceCont(pid, 0); nil != err {
		fmt.Printf("PtraceCont failed, error %s!\n", err)
		return err
	}

	return nil
}

func main() {
	pidptr := flag.Int("pid", 0, "target process's pid")
	flag.Parse()
	if *pidptr < 0 {
		fmt.Printf("-pid param invalid ,please supply target pid!(0 means self)")
		os.Exit(-1)
	}

	if *pidptr == 0 { // parse myself and launch server
		ParseEmbedded()
		fmt.Printf("*pidptr == 0 , exit\n")
		//TODO:: launch server
		os.Exit(0)
	}

	// parse target process, inject libgoinside.so into it
	libraryArray, symbolMap = parseProc(*pidptr)
	if err := inject(*pidptr, "/home/gpmn/Workspace/goinside/Test/libgoinside.so", libraryArray, symbolMap, "main"); nil != err {
		fmt.Printf("inject failed with error %s\n", err)
	}
}
