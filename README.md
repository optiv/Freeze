<h1 align="center">
<br>
<img src=Screenshots/Freeze.jpg height="310" border="2px solid #555">
<br>
Freeze
</h1>



### More Information
If you want to learn more about the techniques utilized in this framework, please take a look at [SourceZero Blog]() 
#

## Description
Freeze is a payload creation tool used for circumventing EDR security controls to execute shellcode in a stealthy manner. Freeze utilizes multiple techniques to not only remove Userland EDR hooks, but to also execute shellcode in such a way that it circumvents other endpoint monitoring controls. 

### Creating A Suspended Process
When a process is created, Ntdll.dll is the first DLL that is loaded. This happens before any EDR DLLs are loaded. This means that there is a bit of a delay before an EDR can be loaded and start hooking and modifying the assembly of system DLLs. In looking at Windows syscalls in Ntdll.dll, we can see that nothing is hooked yet. If we create a process in a suspend state (one that is frozen in time), we can see that no other DLLs are loaded, except for Ntdll.dll. You can also see that no EDR DLLs are loaded, meaning that the syscalls located in Ntdll.dll are unmodified.

<p align="center"> <img src=Screenshots/Suspended_Process.png  border="2px solid #555">

### Address Space Layout Randomization

In order to use this clean suspended process to remove hooks from Freeze loader, we need a way to programmatically find and read the clean suspended process' memory. This is where address space layout randomization (ASLR) comes into play. ASLR is a security mechanism to prevent stack memory corruption-based vulnerabilities. ASLR randomizes the address space inside of a process, to ensure that all memory-mapped objects, the stack, the heap, and the executable program itself, are unique. Now, this is where it gets interesting because while ASLR works, it does not work for position-independent code such as DLLs. What happens with DLLs, (specifically known system DLLs) is that the address space is randomized once at boot time. This means that we don't need to enumerate a remote process information to find the base address of its ntdll.dll because it is the same in all processes including the one that we control. Since the address of every DLL is the same place per boot, we can pull this information from our own process and never have to enumerate the suspended process to find the address. 


<p align="center"> <img src=Screenshots/Base_Address.png border="2px solid #555">

With this information, we can use the API ReadProcessMemory to read a process' memory. This API call is commonly associated with the reading of LSASS as part of any credential-based attack; however, on its own it is inherently not malicious, especially if we are just reading an arbitrary section of memory. The only time ReadProcessMemory will be flagged as part of something suspicious is if you are reading something you shouldn't (like the contents of LSASS). EDR products should never flag the fact that ReadProcessMemory was called, as there are legitimate operational uses for this function and would result in many false positives. 

We can take this a step further by only reading a section of Ntdll.dll where all syscalls are stored -  its .text section, rather than reading the entire DLL. 

Combining these elements, we can programmatically get a copy of the .text section of Ntdll.dll to overwrite our existing hooked .text section prior to executing shellcode.


### ETW Patching
ETW utilizes built-in syscalls to generate this telemetry. Since ETW is also a native feature built into Windows, security products do not need to "hook" the ETW syscalls to access the information. As a result, to prevent ETW, Freeze patches numerous ETW syscalls, flushing out the registers and returning the execution flow to the next instruction. Patching ETW is now default in all loaders. 

### Shellcode

Since only Ntdll.dll is restored, all subsequent calls to execute shellcode need to reside in Ntdll.dll. Using Go (note you can do this in other languages but in Go, its quite easy to implement) we can define and call the NT syscalls needed to allocate, write, and protect the shellcode, effectively skipping the standard calls that are located in kernel32d.dll, and Kernelbase.dll, as these may still be hooked. 


<p align="center"> <img src=Screenshots/Syscalls.png border="2px solid #555">



<p align="center"> <img src=Screenshots/Userland_EDR.png border="2px solid #555">


<p align="center"> <img src=Screenshots/Kernel_EDR.png border="2px solid #555">

## Contributing
Freeze was developed in Golang.

## Install

To install Freeze, run the following commands, or use the compiled binary:
```
go build Freeze.go
```


## Help

```
        ___________                                    
        \_   _____/______   ____   ____ ________ ____  
         |    __) \_  __ \_/ __ \_/ __ \\___   // __ \ 
         |     \   |  | \/\  ___/\  ___/ /    /\  ___/ 
         \___  /   |__|    \___  >\___  >_____ \\___  >
             \/                \/     \/      \/    \/ 
                                        (@Tyl0us)
        Soon they will learn that revenge is a dish... best served COLD...
                 
Usage of ./Freeze:
  -I string
        Path to the raw 64-bit shellcode.
  -O string
        Name of output file (e.g. loader.exe or loader.dll). Depending on what file extension defined will determine if Freeze makes a dll or exe.
  -console
        Only for Binary Payloads - Generates verbose console information when the payload is executed. This will disable the hidden window feature.
  -export string
        For DLL Loaders Only - Specify a specific Export function for a loader to have.
  -process string
        The name of process to spawn. This process has to exist in C:\Windows\System32\. Example 'notepad.exe' (default "notepad.exe")
  -sandbox
        Enables sandbox evasion by checking:
                Is Endpoint joined to a domain?
                Does the Endpoint have more than 2 CPUs?
                Does the Endpoint have more than 4 gigs of RAM?
  -sha256
        Provides the SHA256 value of the loaders (This is useful for tracking)
```

## Binary vs DLL

Freeze can generate either a `.exe` or `.dll` file. In order to specify this, ensure that the `-O` command line option ends with either a `.exe` for binaries or `.dll` for dlls. No other file types are currently supported. In the case of DLL files, Freeze can also add additional export functionality. To do this use the `-export` with specific export function name. 


## Console
Freeze utilizes a technique to first create the process and then move it into the background. This does two things - first it helps keep the process hidden, and second, avoids being detected by any EDR product. Spawning a process right away in the background can be very suspicious and an indicator of maliciousness. Freeze does this by calling the ‘GetConsoleWindow’ and ‘ShowWindow’ Windows function after the process is created and the EDR’s hooks are loaded, and then changes the windows attributes to hidden. Freeze utilizes these APIs rather than using the traditional -ldflags -H=windowsgui, as this is highly signatured and classified in most security products as an Indicator of Compromise.

If the `-console` command-line option is selected, Freeze will not hide the process in the background. Instead, Freeze will add several debug messages displaying what the loader is doing.


## Credit 

* Special thanks to aahmad097 for developing [AlternativeShellcodeExec](https://github.com/aahmad097/AlternativeShellcodeExec)

* Special thanks to mvdan for developing [Garble](https://github.com/burrowers/garble)
