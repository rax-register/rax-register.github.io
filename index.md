# register's accumulator

# register's accumulator

A place for notes on machines from Hack the Box: [https://www.hackthebox.eu](https://www.hackthebox.eu), and other resources I've found and learned from on my journey. 

<p>&nbsp;</p>
## Read this First:

-1- This site is meant as an educational resource and notes repository for my own journey. You must have permission of the machine or site owner before attempting any of the techniques or exploits described here.

-2- Links and tools change over time. For this reason, I have posted a copy of any code or script which I used in the write-up to my own github page in case the current tool continues to receive updates that change functionality or break things. The code itself or links to my github repository are in the **Final Code** section of each post. 

The files on my github repo are not maintained or updated, but in all cases a link to the original source will be included in the write-up. I recommend you follow the process of downloading and altering your own copy of the code from the original source. If you cannot get it working then my github repo can serve as an additional reference, but you will still need to modify the code in most cases.

-3- Commands in a Linux terminal or Windows cmd prompt will be described and shown like this.

Set up our nc listener:

    nc -lvnp 17011

These commands are shown so you can copy the whole line and not have to remove a prompt or other extra characters. In most cases, I also post a screenshot of the command and the expected output.

![](images/nc_listen.png "listener setup")

-4- Smaller code or script examples will appear separately for ease of copying/pasting and maintaining any required formatting.

hello.py:

    #!/usr/bin/python3
    print("Hello World!")

hello.sh:

    #!/bin/bash
    printf "Hello World!\n"

<p>&nbsp;</p>
## Posts

### 1. HTB Lame : 2020-07-07 
[https://rax-register.github.io/2020/07/07/htb-lame.html](https://rax-register.github.io/2020/07/07/htb-lame.html)

### 2. HTB Legacy : 2020-07-08
[https://rax-register.github.io/2020/07/08/htb-legacy.html](https://rax-register.github.io/2020/07/08/htb-legacy.html)

### 3. HTB Blue : 2020-07-08
[https://rax-register.github.io/2020/07/08/htb-blue.html](https://rax-register.github.io/2020/07/08/htb-blue.html)

### 4. HTB Bashed : 2020-07-09
[https://rax-register.github.io/2020/07/09/htb-bashed.html](https://rax-register.github.io/2020/07/09/htb-bashed.html)

### 5. HTB Devel : 2020-07-09
[https://rax-register.github.io/2020/07/09/htb-devel.html](https://rax-register.github.io/2020/07/09/htb-devel.html)
