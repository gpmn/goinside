package main

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
