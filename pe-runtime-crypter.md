---
layout: default
---

# x64 PE Runtime Crypter

## Introduction

In the following examples I will show how we program a PE runtime crypter for x64 applications in C++.
Prior knowledge of C++, WinAPI, PE file format is welcome.
Crypter are used by hackers / penetration testers to evade antivirus detection by encrypting malware. This makes it possible to place and execute the malware on the target system without alarms.

## detection options

Anti-virus software (AV) nowadays has three to detect malware:

(static) signature based detection: the AV checks the hashes (eg MD5, SHA256 ...) of a file against known malware hashes from a large database.

(static) heuristic detection: the AV checks a file for code characteristics e.g. functions which are known used by malware.

dynamic detection: in this case, the AV executes the file in a "safe environment" like a virtual machine (VM) or sandbox to analyze the behavior of the file at runtime.

Our crypter will prevent signature based detection and also mostly heuristic detection of AVs.
At the end I will give some tips to prevent dynamic analysis and also make it a little harder for reverse engineers and security researchers.
The main task of our crypter is to obfuscate an executable through encryption and thereby bypass the signature-based detection of AVs. To ensure this, the decrypted code must must be executed in memory so that it never touches the hard disk.

## Why C++?
Firstly because C++ is compiled which in itself is a security layer if we don't want someone to be able to easily inspect our source code. Also, C++ is a native programming language, which means that C/C++ is compiled directly into assembly, which is interpreted by the processor. C# or Java are in contrast to C++ unhandled programming languages which are interpreted by a runtime environment. Executables of unhandled languages are compiled into an intermediate product (Bytecode) that is understandable for the runtime environment.
This Bytecode is much easier to reverse and read than assembly.
And finally, with C++ we have the possibility to obfuscate our source code really effectively on compiler level (e.g. by control flow flattering).

## Why x64?
I think most users have moved to 64-bit systems these days.
This is to our advantage because malware is less likely to be detected if we develop it for 64-bit systems.

As you can see, malware is very much about operating under the radar of security analysts/researchers and AVs.

## steps to do:

# stub development
the stub program is our "dummy" that later holds our malware (or any other x64 PE) in encrypted form. So the "only" thing our stub will do is:
- search inside itself for the embedded resource
- decrypt the found resource
- execute the decrypted resource in memory (hardest part)


# crypter development
the crypter holds our hardcoded stub we programmed before (as a template) and writes it to disk. Then it reads the PE file we want to obfuscate and inserts it in encrypted form as a resource into our stub.
- read the input PE 
- validate input file as x64
- encrypt data from input PE
- write the stub to disk
- add encrypted data as resource to the stub


## Lets code

We start with the stub. first we create a function to find the encrypted resource. This is the file which will be attached later by our crypter. The first two parameters the function expects is the resource name and the resource type to find the code. 
...


Now we write the main function. First we hide the console window. After that we call
the GetResource function with our parameters and decrypt the returned coder byte by byte with XOR and our key (resource name "132", resource type "BIN", and the key "k" are freely selectable, but must be identical later in the crypter).
...


Finally we have to execute the decrypted code. Normally the OS Loader does all the work (mapping sections of an executable into memory, performing address relocation fix-ups if necessary, resolving function addresses and creating Import Address Table ... ) to execute a PE file correctly on the system. The difficulty here is that we are not running an executable from disk but from memory.
We could write our own PE loader algorithm like this POC by Amit Malik https://securityxploded.com/memory-execution-of-executable.php
or implement an extended, more complex loader like this https://github.com/abhisek/Pe-Loader-Sample/blob/master/src/PeLdr.cpp from abhisek.

I decided to use a process hollowing technique which is a bit easier to implement.
We create a new process in suspended mode into which we can inject the code and then run it.
The important things we do here are:

`CreateProcess`: creating new process in a suspended mode for the injection.

`GetThreadContext`: retrieves the context of the specified thread.

`VirtualAllocEx`: allocates memory within the suspended process's address space.

`WriteProcessMemory`: writes data of the PE file into the allocated memory of the suspended process.

`SetThreadContext`: sets the RCX register to the entry point of the executable.

`ResumeThread`: resumes the thread of the suspended process.

...

We compile the program in release mode and our stub is ready!


Now we have to write our crypter. Our crypter is also a CLI application so we read our input PE (the file we want to encrypt) as argument.
We also create a byte array as a placeholder for the raw code of our compiled stub.
We change this at the end otherwise our IDE will lag or be functionally compromised because the byte array will be very large.
...

Now we check the header of the image to make sure we are working with a x64 PE.
...

And we encrypt the data with XOR and the key "k" exactly like in the stub before.
...

Our crypter must now write the stub to disk.
...

Now we have to add the encrypted data as resource to our stub. For this we use `BeginUpdateResource`, `UpdateResource` and `EndUpdateResource`. As I mentioned before we have to make sure that we use the same resource name and resource type as in the stub. Otherwise our stub program will not find a resource to work with.
...

Before compiling we insert the raw code as byte array into our code.
I use the HxD hexeditor to open my stub.exe and export the raw code to a .c file.
!(https://github.com/Ricky5panish/Ricky5panish.github.io/blob/main/assets/images/embed.gif)

This .c file contains a byte array from our stub which we now simply copy and replace with our placeholder above the main function.
We also compile our crypter in release mode aaand...

Congratulations we have coded our own x64 PE runtime crypter!

## Lets test!
I have taken a new C++ window application for testing.
!(https://github.com/Ricky5panish/Ricky5panish.github.io/blob/main/assets/images/test.gif)

### It works :)

In the task manager we see our window application running in a new process under our stub.
!(https://github.com/Ricky5panish/Ricky5panish.github.io/blob/main/assets/images/taskmgr.png)

If we take a look at the stub with CFF Explorer we can find our attached file under "resources". Also it is clear to see that the file is encrypted.
!(https://github.com/Ricky5panish/Ricky5panish.github.io/blob/main/assets/images/encrypted.png)

I created a x64 powershell_reverse_tcp with Metasploit to test the detection rate.
Here we see the fresh payload from metasploit
!(https://github.com/Ricky5panish/Ricky5panish.github.io/blob/main/assets/images/msfPayload.png)

And here the crypted payload
!(https://github.com/Ricky5panish/Ricky5panish.github.io/blob/main/assets/images/crypted.png)

## Tips for improvement
- In any case, a better encryption method like AES would be much saver as some AVs are able to crack XOR. 
- Hardcoded encryption keys are also horrible for security. I strongly recommend to use functions for building such sensible data at runtime.
- A different technique to run our PE could also decrease the detection rate because process hollowing is already noticeable.
- Adding a code signature to our stub also makes the application look more serious to AVs.
- Theoretically you could also program the whole stub in another more exotic language like GoLang.


- To avoid dynamic analysis like sandboxing we can take a look at the hardware specifications of the system at the beginning of our stub. So we can prevent further execution of our code if...
1. hard disk < 100 GB
2. RAM < 2 GB
3. CPU cores < 2

- An idea could also be a user interaction like a MSG box to prevent automated analysis of further code.

- We can also look for VM artifacts to identify a virtualized environment.
This could be files like "C:\Windows\System32\VBox*.dll" but also registry entries.

- Checking running processes coming from analysis tools (Ghidra, IDA, x64dbg, Wireshark ...) can also be very useful.


I hope you could learn something :)
