# register's accumulator

A simple place to keep notes and write-ups about Hack the Box machines and other resources.

<p>&nbsp;</p>

## Read this First:

-1- This site is meant as an educational resource and notes repository for my own journey. You must have permission of the machine or site owner before attempting any of the techniques or exploits described here.

-2- Links and tools change over time. For this reason, I have posted a copy of any code or script which I used in the write-up to my own github page in case the current tool continues to receive updates that change functionality or break things. The code itself or links to my github repository are in the **Final Code** section of each post. 

The files on my github repo are not maintained or updated from what I used to solve the challenge, but in all cases a link to the original source will be included in the write-up. I recommend you follow the process of downloading and altering your own copy of the code from the original source. If you cannot get it working then my github repo can serve as an additional reference, but you will still need to modify the code in most cases.

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

-5- There are multiple ways to solve most of these challenges, and definitely multiple tools or variants on command syntax. For the easier machines, I try to provide a sample of different resources, tools, and syntax to use instead of sticking to only a few tried and true tricks or commands. The trade-off is that my specific commands or sequence for solving a machine may not be the most elegant or simple. 

<p>&nbsp;</p>
