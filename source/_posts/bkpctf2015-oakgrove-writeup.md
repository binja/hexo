title: Boston Key Party CTF 2015 - Oak Grove (rev300) Writeup
date: 2015-03-02 21:54:08
tags:
- writeup
- rev
---

> This crappy 3ds homebrew is protected by some anti-piracy scheme. Can you crack it? : 300
> http://bostonkeyparty.net/3ds.3dsx.aea77af56f33d08026adf0a3c9fcdaf5OD

The binary is a 3DS homebrew for NINJHAX and is in 3DSX format. After several minutes of googling, we found out that there is no IDA Loader for 3DSX at the moment of BKP. We wrote simple IDA Loader for 3DSX and analyzed the binary using IDA. (We don't publish the loader because another player published a better one after the BKP :) https://github.com/0xEBFE/3DSX-IDA-PRO-Loader)

The homebrew is obfuscated by the virtual machine. This virtual machine is slightly buggy (missing break in a switch case, pop on an empty stack). Manual analysis found that the VM code reads 16 bytes from a file 'SHiT' and compares the contents char by char with embedded values. The VM code increments a counter (dword_33BC0) as characters match the embedded values. If the counter is 100 at the end of VM code, the homebrew outputs 'Winner, please submit your flag!'.

As reverse-engineering of the whole obfuscated VM code seemed to be troublesome and easy to mistake, we implemented the same virtual machine in Python and did bruteforce for SHiT.

```python
#!/usr/bin/env python3
import sys
import string

FLAGLEN = 16
CHARS   = bytes(string.printable, 'ascii')
CODE    = b''
with open('3ds.3dsx.aea77af56f33d08026adf0a3c9fcdaf5OD', 'rb') as f:
    f.seek(0x2abd4)
    CODE = f.read(0x1d0)

class VirtualMachine(object):

    def __init__(self, code, flag):
        self.dword_33BC0 = self.R7 = self.ip = 0
        self.stack = []
        self.flag = flag
        self.code = code

    def getb(self):
        val = self.code[self.ip]
        self.ip += 1
        return val

    def jmp(self, n):
        self.ip += n

    def push(self, val):
        self.stack.append(val)

    def pop(self):
        try:
            return self.stack.pop()
        except IndexError:
            self.log('empty pop')
            return 0

    def log(self, msg):
        #print('[*] %04x: %s' % (self.ip, msg), file=sys.stderr)
        pass

    def inst11(self):
        arg1 = self.getb()
        if self.R7 == 0:
            self.jmp(arg1)
        self.inst57()

    def inst57(self):
        arg1 = self.getb()
        self.push((self.pop() ^ arg1) & 0xff)

    def inst48(self):
        filename = ''
        ch = -1
        while ch != 0:
            ch = self.pop()
            filename += chr(ch)
        self.log('fopen("%s", "r")' % filename)

    def inst51(self):
        self.log('exit(0)')
        raise Exception('exit')

    def inst17(self):
        self.pop()

    def inst40(self):
        self.log('getchar()')
        self.push(self.flag.pop())

    def inst0(self):
        self.log('unk_0')
        # Not Implemented

    def inst52(self):
        arg1 = self.getb()
        self.push((self.pop() - arg1) & 0xff)

    def inst49(self):
        arg1 = self.getb()
        self.push(arg1)

    def inst27(self):
        self.push(0)

    def inst20(self):
        self.push(len(self.stack))

    def inst59(self):
        v1 = self.pop()
        v2 = self.pop()
        self.push(v1)
        self.push(v2)

    def inst24(self):
        self.dword_33BC0 += 1

    def inst46(self, ):
        self.push((self.pop() * arg1) & 0xff)

    def inst43(self, ):
        arg1 = self.getb()
        if self.R7 != 0:
            self.jmp(arg1)
            self.R7 = 1

    def inst42(self):
        self.push((self.pop() + 1) & 0xff)

    def inst38(self):
        self.push(0)

    def inst37(self):
        self.push((self.pop() - 1) & 0xff)

    def inst36(self):
        self.log('cmp')
        arg1 = self.getb()
        val = self.pop()
        self.R7 = 1 if val == arg1 else 0

    def inst34(self):
        arg1 = self.getb()
        self.push((self.pop() + arg1) & 0xff)

    def run(self):
        instdict = {
            11:self.inst11,
            57:self.inst57,
            48:self.inst48,
            51:self.inst51,
            17:self.inst17,
            56:self.inst17, # same
            40:self.inst40,
            0:self.inst0,
            52:self.inst52,
            49:self.inst49,
            27:self.inst27,
            20:self.inst20,
            59:self.inst59,
            24:self.inst24,
            46:self.inst46,
            43:self.inst43,
            42:self.inst42,
            38:self.inst38,
            37:self.inst37,
            36:self.inst36,
            34:self.inst34,
        }

        while self.ip < len(self.code):
            inst = self.getb() - 0x3f
            if inst not in instdict:
                self.log('Undefined instruction')
                continue

            try:
                instdict[inst]()
            except Exception as e:
                if e.args[0] == 'exit':
                    break
                else:
                    raise e

        return self.dword_33BC0

def _bruteforce_flag(flag):
    cntdict = {}
    for i in (i for i, v in enumerate(flag) if v == 0):
        for ch in CHARS:
            flagcand = flag[::]
            flagcand[i] = ch

            vm = VirtualMachine(CODE, flagcand[::])
            cntdict[tuple(flagcand)] = vm.run()

    return cntdict

def bruteforce_flag(flag, prevcnt):
    cntdict = _bruteforce_flag(flag)

    for k in (k for k in cntdict if cntdict[k] > prevcnt):
        cnt = cntdict[k]
        if cnt == 100:
            print(bytes(k).decode('ascii')[::-1])
            quit()
        else:
            bruteforce_flag(list(k), cnt)

def main():
    flag = [0] * FLAGLEN
    bruteforce_flag(flag, 0)

if __name__ == '__main__':
    main()
```

```
% time ./bruteforce.py
r_u_t34m_g473w4y
./bruteforce.py  6.02s user 0.00s system 99% cpu 6.021 total
%
```

written by op([@6f70](https://twitter.com/6f70))
