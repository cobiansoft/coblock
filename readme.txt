Cobian Locker (coblock)
©2024 Luis Cobian, CobianSoft
https://www.cobiansoft.com

Cobian Locker is a command line utility that can be used to encrypt and decrypt individual files or folders.

For usage, run the utility with the help verb as in

coblock help

The program can be run in Windows (64 bits), Windows (32 bits) , Windows for ARM (64 bits only), OSX (64 bits),
OSX-ARM (64 bits), Linux (64 bits), Linux-ARM (64 bits) or Linux-ARM (32 bits).

There are no dependences for this program (everything is included in the executable).

Minimum requirements on Windows: Windows 10 (1607) or newer

Minimum requirements on Windows Server: Windows Server 2012 or newer

Minimum requirements on Linux: Ubuntu 20.04 or newer, SUSE 15.5 or newer, Red Hat, 8 or newer, Fedora 40 or newer, Debian 12 or newer CentOS 9 or newer.

Minimum requirements on OSX: OSX 13 or newer

INSTALLATION 

As this is a single executable, you could execute it from any directory. 

For convenience, you could just copy it to c:\Windows\System32 in Windows or to /usr/local/bin on Linux or OSX.

Just remember to add the Executable flag to the program on Linux or OSX in order to make it runnable:

sudo chmod +x /usr/local/bin/coblock 

SOURCE CODE

The program is distributed under the GPLv3 license. The source code is available at

https://github.com/cobiansoft/coblock

BUILDING THE PROGRAM

The program is written in C# using .NET 8.0 (Core). Open the solution in Visual Studio (I use VS 2022) and just publish the solution
for your favorite platform checking the options:

* Produce single file
* Trim unused code 
* Enable ReadyToRun compilation (where available) 


